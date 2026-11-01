#!/usr/bin/env python3
"""
pki2kdbx.py - build a KeePassXC database from a directory of PEM certs/keys.

Scans a directory for X.509 certificates and private keys,
pairs keys to their certs by public key,
computes the metadata you would otherwise type by hand and emits a KeePass 2 XML file that `keepassxc-cli import` turns into a KDBX.

Design notes:
  * Entry UUIDs are derived from the certificate's SHA-256 fingerprint, so re-running is idempotent,
    and a rotated cert becomes a new entry rather than overwriting the old one.
  * Private keys are re-encoded as unencrypted PKCS#8 PEM inside the vault.
  * A manifest.tsv is written alongside, listing each certificate's SHA-256 fingerprint and metadata,
    so you can match a vault entry to a cert on disk without opening the vault.

Usage:
    pki2kdbx.py --src ./pem-tree --out pki.xml [--manifest manifest.tsv]
                [--root-group PKI] [--group-map groups.tsv] [--dry-run]
    pki2kdbx.py --src ./pem-tree --db pki.kdbx [--password-file pw]
                [--key-file key] [--no-password] [--chain none]

groups.tsv maps a cert CN to a group path:
    web01.example.com<TAB>leafs/web
    Example Root CA<TAB>root

Unmapped certs are grouped heuristically: self-signed CA -> root, other CA -> intermediate, everything else -> leafs.
"""

from __future__ import annotations

import argparse
import base64
import getpass
import hashlib
import os
import re
import secrets
import shutil
import subprocess
import sys
import tempfile
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from xml.sax.saxutils import escape

try:
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import dsa, ec, ed448, ed25519, rsa
    from cryptography.x509.oid import ExtensionOID, NameOID
except ImportError:
    sys.exit("requires: python3 -m pip install cryptography")


@dataclass
class Item:
    cert: x509.Certificate
    path: Path
    key_pem: bytes | None = None
    key_path: Path | None = None
    chain: list[x509.Certificate] = field(default_factory=list)
    title: str = ""

    @property
    def cn(self) -> str:
        attrs = self.cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)
        return str(attrs[0].value) if attrs else self.path.stem

    @property
    def fingerprint(self) -> str:
        return self.cert.fingerprint(hashes.SHA256()).hex()

    @property
    def is_ca(self) -> bool:
        try:
            return bool(
                self.cert.extensions.get_extension_for_oid(
                    ExtensionOID.BASIC_CONSTRAINTS
                ).value.ca
            )
        except x509.ExtensionNotFound:
            return False

    @property
    def is_self_signed(self) -> bool:
        return self.cert.issuer == self.cert.subject


def load_cert(path: Path) -> x509.Certificate | None:
    try:
        return x509.load_pem_x509_certificate(path.read_bytes())
    except Exception:  # noqa: BLE001, S110 - probe PEM, then fall back to DER
        pass
    try:
        return x509.load_der_x509_certificate(path.read_bytes())
    except Exception:  # noqa: BLE001 - not a certificate
        return None


def load_key(path: Path):
    data = path.read_bytes()
    for loader in (
        serialization.load_pem_private_key,
        serialization.load_der_private_key,
    ):
        try:
            return loader(data, password=None)
        except Exception:  # noqa: BLE001, S112 - try the next loader
            continue
    return None


def pubkey_id(key) -> bytes:
    return key.public_bytes(
        serialization.Encoding.DER,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    )


PEM_CERT = re.compile(
    rb"-----BEGIN CERTIFICATE-----.+?-----END CERTIFICATE-----", re.DOTALL
)


def load_certs(path: Path) -> list[x509.Certificate]:
    """Every certificate in the file, not just the first: a directory of
    *_chain.crt bundles would otherwise silently contribute only leaf certs."""
    data = path.read_bytes()
    out = []
    for block in PEM_CERT.findall(data):
        try:
            out.append(x509.load_pem_x509_certificate(block))
        except Exception:  # noqa: BLE001, S110 - skip malformed block
            pass
    if out:
        return out
    try:
        return [x509.load_der_x509_certificate(data)]
    except Exception:  # noqa: BLE001 - not a DER certificate
        return []


def looks_encrypted_key(data: bytes) -> bool:
    head = data[:200]
    return (
        b"BEGIN" in head
        and b"PRIVATE KEY" in head
        and (b"ENCRYPTED" in data[:400] or b"Proc-Type: 4,ENCRYPTED" in data[:400])
    )


def scan(src: Path):
    certs: dict[bytes, Item] = {}
    keys: dict[bytes, tuple[Path, object]] = {}
    skipped: list[tuple[Path, str]] = []

    paths = [src] if src.is_file() else sorted(src.rglob("*"))
    for path in paths:
        if not path.is_file() or path.name.startswith("."):
            continue
        found = load_certs(path)
        if found:
            for cert in found:
                item = Item(cert=cert, path=path)
                certs.setdefault(item.fingerprint, item)
            continue
        raw = path.read_bytes()
        key = load_key(path)
        if key is not None:
            keys[pubkey_id(key.public_key())] = (path, key)
        elif looks_encrypted_key(raw):
            skipped.append((path, "encrypted private key (decrypt it first)"))
        elif b"CERTIFICATE REQUEST" in raw or b"X509 CRL" in raw:
            pass  # CSRs and CRLs are expected company
        elif b"BEGIN CERTIFICATE" in raw or b"BEGIN" in raw[:400]:
            skipped.append((path, "unparsable PEM"))

    for item in certs.values():
        hit = keys.get(pubkey_id(item.cert.public_key()))
        if hit:
            item.key_path, key = hit
            item.key_pem = key.private_bytes(
                serialization.Encoding.PEM,
                serialization.PrivateFormat.PKCS8,
                serialization.NoEncryption(),
            )
    return list(certs.values()), skipped


def build_chain(item: Item, by_subject: dict[str, list[Item]], depth: int = 8):
    """Walk issuer -> subject up to a root. Returns [intermediate, ..., root]."""
    chain, seen = [], {item.fingerprint}
    cur = item
    for _ in range(depth):
        if cur.is_self_signed:
            break
        parents = [
            c
            for c in by_subject.get(cur.cert.issuer.rfc4514_string(), [])
            if c.fingerprint not in seen
        ]
        if not parents:
            break
        parent = parents[0]
        chain.append(parent.cert)
        seen.add(parent.fingerprint)
        cur = parent
    return chain


def key_desc(key) -> tuple[str, int]:
    if isinstance(key, rsa.RSAPublicKey):
        return "RSA", key.key_size
    if isinstance(key, ec.EllipticCurvePublicKey):
        return f"EC/{key.curve.name}", key.key_size
    if isinstance(key, ed25519.Ed25519PublicKey):
        return "Ed25519", 256
    if isinstance(key, ed448.Ed448PublicKey):
        return "Ed448", 456
    if isinstance(key, dsa.DSAPublicKey):
        return "DSA", key.key_size
    return type(key).__name__, 0


def sans(cert: x509.Certificate) -> str:
    try:
        ext = cert.extensions.get_extension_for_oid(
            ExtensionOID.SUBJECT_ALTERNATIVE_NAME
        ).value
    except x509.ExtensionNotFound:
        return ""
    val = lambda n: str(getattr(n, "value", n))
    out = [val(n) for n in ext.get_values_for_type(x509.DNSName)]
    out += [val(n) for n in ext.get_values_for_type(x509.IPAddress)]
    out += [val(n) for n in ext.get_values_for_type(x509.RFC822Name)]
    return ", ".join(out)


def na_utc(cert: x509.Certificate) -> datetime:
    return getattr(cert, "not_valid_after_utc", None) or cert.not_valid_after.replace(
        tzinfo=UTC
    )


def slug(cn: str) -> str:
    """Convert a CN into a group-path component.

    Strips a trailing 'CA', 'Root CA', or 'Intermediate CA', then lowercases
    and joins non-alphanumerics with '-'.
    Lossy: distinct CNs may collapse to the same slug.
           Use --group-map for exact group names.
    """
    s = re.sub(r"\s+(Intermediate|Root)?\s*CA$", "", cn, flags=re.IGNORECASE)
    s = re.sub(r"[^A-Za-z0-9]+", "-", s).strip("-").lower()
    return s or "unnamed"


def classify(items: list[Item]) -> dict[str, str]:
    """fingerprint -> group. Self-signed is not the same as top-of-hierarchy:
    a homelab that never distributes a root can have self-signed issuing CAs
    that are the real trust anchors, one per service."""
    # a CA that is itself signed by someone else proves its parent is a root
    signs_a_ca = {
        it.cert.issuer.rfc4514_string()
        for it in items
        if it.is_ca and not it.is_self_signed
    }
    issues_anything = {
        it.cert.issuer.rfc4514_string()
        for it in items
        if it.cert.issuer != it.cert.subject
    }
    out = {}
    for it in items:
        if not it.is_ca:
            # service = the intermediate that signed it
            issuer_cn = next(
                (
                    a.value
                    for a in it.cert.issuer.get_attributes_for_oid(NameOID.COMMON_NAME)
                ),
                "unknown",
            )
            out[it.fingerprint] = f"leafs/{slug(str(issuer_cn))}"
            continue
        subj = it.cert.subject.rfc4514_string()
        if not it.is_self_signed:
            out[it.fingerprint] = f"intermediate/{slug(it.cn)}"
        elif subj in signs_a_ca:
            out[it.fingerprint] = "root"  # parents another CA
        elif subj in issues_anything:
            out[it.fingerprint] = f"intermediate/{slug(it.cn)}"
        else:
            out[it.fingerprint] = "root"  # signs nothing: archival
    return out


def group_for(item: Item, overrides: dict[str, str], roles: dict[str, str]) -> str:
    return overrides.get(item.cn) or roles.get(item.fingerprint, "leafs")


def det_uuid(*parts: str) -> str:
    h = hashlib.sha256("\x00".join(parts).encode()).digest()[:16]
    return base64.b64encode(h).decode()


def s(key: str, value: str, protect: bool = False) -> str:
    attr = ' ProtectInMemory="True"' if protect else ""
    return (
        f"<String><Key>{escape(key)}</Key><Value{attr}>{escape(value)}</Value></String>"
    )


def build_xml(
    items: list[Item],
    root_group: str,
    overrides: dict[str, str],
    chain_mode: str = "auto",
):
    by_subject: dict[str, list[Item]] = {}
    for it in items:
        by_subject.setdefault(it.cert.subject.rfc4514_string(), []).append(it)

    for it in items:
        it.chain = build_chain(it, by_subject)

    roles = classify(items)
    stored = {it.fingerprint for it in items}

    groups: dict[str, list[Item]] = {}
    for it in items:
        groups.setdefault(group_for(it, overrides, roles), []).append(it)

    # group path -> nested tree; the "" key of a node holds its entries
    tree: dict = {}
    for gname, members in groups.items():
        node = tree
        for part in [p for p in gname.split("/") if p]:
            node = node.setdefault(part, {})
        node[""] = members

    out = [
        '<?xml version="1.0" encoding="UTF-8"?>',
        "<KeePassFile>",
        "  <Meta><Generator>pki2kdbx</Generator></Meta>",
        "  <Root>",
        (
            f"    <Group><UUID>{det_uuid('group', '')}</UUID>"
            f"<Name>{escape(root_group)}</Name>"
        ),
    ]

    def emit(node: dict, path: str, depth: int) -> None:
        pad = "  " * depth
        for name in sorted(k for k in node if k != ""):
            sub = f"{path}/{name}" if path else name
            out.append(
                f"{pad}<Group><UUID>"
                f"{det_uuid('group', sub)}</UUID>"
                f"<Name>{escape(name)}</Name>"
            )
            emit(node[name], sub, depth + 1)
            out.append(f"{pad}</Group>")
        members = node.get("")
        if not members:
            return
        counts: dict[str, int] = {}
        for it in members:
            counts[it.cn.lower()] = counts.get(it.cn.lower(), 0) + 1
        for it in sorted(members, key=lambda i: i.cn.lower()):
            it.title = (
                f"{it.cn} ({format(it.cert.serial_number, 'x')[-8:]})"
                if counts[it.cn.lower()] > 1
                else it.cn
            )
            for line in entry_xml(it, path, stored, chain_mode).splitlines():
                out.append(pad + "  " + line.strip())

    emit(tree, "", 3)

    out += ["    </Group>", "  </Root>", "</KeePassFile>"]
    return "\n".join(out)


def cert_fp(c: x509.Certificate) -> str:
    return c.fingerprint(hashes.SHA256()).hex()


def describe(it: Item, gname: str, stored: set[str], chain_mode: str) -> dict:
    """Single source of truth for what an entry contains, shared by the XML
    writer and the direct-to-KDBX writer."""
    cert = it.cert
    alg, bits = key_desc(cert.public_key())
    nb = getattr(cert, "not_valid_before_utc", None) or cert.not_valid_before.replace(
        tzinfo=UTC
    )
    na = getattr(cert, "not_valid_after_utc", None) or cert.not_valid_after.replace(
        tzinfo=UTC
    )
    fp = ":".join(
        it.fingerprint[i : i + 2] for i in range(0, len(it.fingerprint), 2)
    ).upper()

    notes = [
        f"issuer: {cert.issuer.rfc4514_string()}",
        f"subject: {cert.subject.rfc4514_string()}",
        f"valid: {nb:%Y-%m-%d} -> {na:%Y-%m-%d}",
        f"sha256: {fp}",
    ]
    if it.chain:
        notes.append(
            "chain: " + " <- ".join(c.subject.rfc4514_string() for c in it.chain)
        )

    # A chain blob per leaf duplicates every CA cert once per leaf and drifts
    # the moment an intermediate is reissued. In "auto" mode only attach the
    # issuers that are NOT already stored as their own entry.
    chain = it.chain
    if chain_mode == "none":
        chain = []
    elif chain_mode == "auto":
        chain = [c for c in chain if cert_fp(c) not in stored]

    blobs = [("cert.pem", cert.public_bytes(serialization.Encoding.PEM))]
    if it.key_pem:
        blobs.append(("key.pem", it.key_pem))
    if chain:
        blobs.append(
            (
                "chain.pem",
                b"".join(c.public_bytes(serialization.Encoding.PEM) for c in chain),
            )
        )

    return {
        "uuid": bytes.fromhex(it.fingerprint[:32]),
        "title": it.title or it.cn,
        "username": cert.subject.rfc4514_string(),
        "url": "",
        "notes": "\n".join(notes),
        "tags": ["pki", gname.split("/")[-1], f"expires-{na:%Y}"],
        "attrs": {
            "serial": format(cert.serial_number, "X"),
            "subject": cert.subject.rfc4514_string(),
            "issuer": cert.issuer.rfc4514_string(),
            "notBefore": f"{nb:%Y-%m-%dT%H:%M:%SZ}",
            "notAfter": f"{na:%Y-%m-%dT%H:%M:%SZ}",
            "sha256": fp,
            "keyAlg": f"{alg} {bits}",
            "san": sans(cert),
            "isCA": "yes" if it.is_ca else "no",
            "source": str(it.path),
        },
        "protected": {"serial"},
        "blobs": blobs,
    }


def entry_xml(it: Item, gname: str, stored: set[str], chain_mode: str) -> str:
    d = describe(it, gname, stored, chain_mode)
    nb = d["attrs"]["notBefore"]
    na = d["attrs"]["notAfter"]
    now = f"{datetime.now(UTC):%Y-%m-%dT%H:%M:%SZ}"
    body = [
        "        <Entry>",
        f"          <UUID>{base64.b64encode(d['uuid']).decode()}</UUID>",
        "          <Times>",
        f"            <CreationTime>{nb}</CreationTime>",
        f"            <LastModificationTime>{now}</LastModificationTime>",
        f"            <LastAccessTime>{now}</LastAccessTime>",
        f"            <ExpiryTime>{na}</ExpiryTime>",
        "            <Expires>True</Expires>",
        "            <UsageCount>0</UsageCount>",
        f"            <LocationChanged>{now}</LocationChanged>",
        "          </Times>",
        f"          {s('Title', d['title'])}",
        f"          {s('UserName', d['username'])}",
        f"          {s('URL', d['url'])}",
        f"          {s('Notes', d['notes'])}",
    ]
    for k, v in d["attrs"].items():
        body.append(f"          {s(k, v, k in d['protected'])}")
    for name, data in d["blobs"]:
        body.append(
            f"          <Binary><Key>{escape(name)}</Key>"
            f"<Value>{base64.b64encode(data).decode()}</Value></Binary>"
        )
    body.append(f"          <Tags>{escape(','.join(d['tags']))}</Tags>")
    body.append("        </Entry>")
    return "\n".join(body)


def write_staging_keyfile(path: Path) -> None:
    """Write a KeePassXC XML v2 key file; raw 32-byte files are legacy."""
    key = secrets.token_bytes(32)
    checksum = hashlib.sha256(key).digest()[:4].hex().upper()
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "w") as fh:
        fh.write(
            '<?xml version="1.0" encoding="UTF-8"?>\n'
            "<KeyFile>\n"
            "  <Meta>\n"
            "    <Version>2.0</Version>\n"
            "  </Meta>\n"
            "  <Key>\n"
            f'    <Data Hash="{checksum}">{key.hex().upper()}</Data>\n'
            "  </Key>\n"
            "</KeyFile>\n"
        )


def _run(
    cmd: list[str], stdin_text: str = "", interactive: bool = False
) -> subprocess.CompletedProcess:
    """interactive=True leaves the terminal attached, so keepassxc-cli prompts
    itself and the password never passes through this process."""
    if interactive:
        return subprocess.run(cmd, check=False)
    # start_new_session drops the controlling terminal, so keepassxc-cli reads
    # the piped secret instead of also painting a prompt on the user's tty
    return subprocess.run(
        cmd,
        check=False,
        input=stdin_text.encode(),
        capture_output=True,
        start_new_session=True,
    )


def write_db(
    db_path: Path,
    items: list[Item],
    overrides: dict[str, str],
    chain_mode: str,
    root_group: str,
    keyfile: Path | None,
    password: str | None,
    native_prompt: bool,
    dry_run: bool = False,
) -> int:
    """Build an XML in RAM, import it into a throwaway vault, merge that into
    the target, delete both. keepassxc-cli has no 'write into existing db'
    command, and pykeepass' writer corrupts KDBX 3.1 headers, so this drives
    the two operations that are actually proven to round-trip.

    password=None means the vault has no password (key file only).
    native_prompt=True means do not collect the password at all: leave stdin
    attached to the terminal so keepassxc-cli asks for it itself.

    When the target exists, the staging vault uses a throwaway key file rather
    than the target password. That keeps the password prompt attached to the
    real vault instead of asking for a new password for the staging vault.
    """
    by_subject: dict[str, list[Item]] = {}
    for it in items:
        by_subject.setdefault(it.cert.subject.rfc4514_string(), []).append(it)
    for it in items:
        it.chain = build_chain(it, by_subject)
        it.title = it.title or it.cn

    xml = build_xml(items, root_group, overrides, chain_mode)

    # the XML holds every private key in the clear: keep it in RAM only
    shm = Path("/dev/shm") if Path("/dev/shm").is_dir() else None
    fd, xml_path = tempfile.mkstemp(
        prefix="pki-", suffix=".xml", dir=str(shm) if shm else None
    )
    os.fchmod(fd, 0o600)
    with os.fdopen(fd, "w") as fh:
        fh.write(xml)

    work = Path(tempfile.mkdtemp(prefix="pki-staging-"))
    staging = work / "staging.kdbx"
    merging = db_path.exists()
    has_password = not merging and (password is not None or native_prompt)
    pw_in = f"{password}\n" * 2 if has_password and password else ""

    try:
        imp = ["keepassxc-cli", "import", "-q"]
        if has_password:
            imp.append("-p")
        if merging:
            staging_key = work / "staging.key"
            write_staging_keyfile(staging_key)
            imp += ["--set-key-file", str(staging_key)]
        elif keyfile:
            imp += ["--set-key-file", str(keyfile)]
        imp += [xml_path, str(staging)]
        r = _run(imp, pw_in, interactive=native_prompt and has_password)
        if r.returncode != 0:
            if native_prompt:
                print("import failed (see output above)", file=sys.stderr)
            else:
                print((r.stderr + r.stdout).decode().strip(), file=sys.stderr)
            return 1

        if merging:
            mer = ["keepassxc-cli", "merge"]
            if keyfile:
                mer += ["-k", str(keyfile)]
            if password is None and not native_prompt:
                mer += ["--no-password"]
            mer += [
                "--key-file-from",
                str(staging_key),
                "--no-password-from",
            ]
            mer += ["--dry-run"] if dry_run else []
            mer += [str(db_path), str(staging)]
            r = _run(
                mer, f"{password}\n" if password else "", interactive=native_prompt
            )
            out = "" if native_prompt else (r.stdout + r.stderr).decode().strip()
            if r.returncode != 0:
                print(out or "merge failed (see output above)", file=sys.stderr)
                return 1
            if dry_run and out:
                # the plan is the whole point of a dry run
                print(
                    "\n".join(
                        l
                        for l in out.splitlines()
                        if not l.lower().startswith(
                            ("enter password", "repeat password")
                        )
                    )
                )
        else:
            if dry_run:
                print(f"would create {db_path}")
                return 0
            shutil.move(str(staging), str(db_path))
            print(f"created {db_path}")

        print(
            f"{len(items)} certificate(s) {'planned for' if dry_run else 'written to'} "
            f"{db_path}"
        )
        return 0
    finally:
        os.unlink(xml_path)
        shutil.rmtree(work, ignore_errors=True)


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--src", required=True, type=Path)
    ap.add_argument("--out", type=Path, help="write KeePass XML here")
    ap.add_argument("--db", type=Path, help="write straight into this .kdbx")
    ap.add_argument("--key-file", type=Path, help="vault key file, if it has one")
    ap.add_argument(
        "--no-password",
        action="store_true",
        help="vault is protected by a key file only",
    )
    ap.add_argument(
        "--password-file",
        type=Path,
        help="read the vault password from this file instead of prompting",
    )
    ap.add_argument(
        "--native-prompt",
        action="store_true",
        help="let keepassxc-cli ask for the password itself; still a terminal "
        "prompt, but the secret never enters this process (prompts once for "
        "an existing vault, twice when creating one)",
    )
    ap.add_argument("--manifest", type=Path)
    ap.add_argument("--root-group", default="PKI")
    ap.add_argument("--group-map", type=Path)
    ap.add_argument(
        "--chain",
        choices=["auto", "always", "none"],
        default="auto",
        help="attach chain.pem per entry? auto = only issuers that "
        "are not stored as their own entry (default)",
    )
    ap.add_argument("--dry-run", action="store_true")
    a = ap.parse_args()

    if not a.src.exists():
        print(f"no such path: {a.src}")
        return 1

    overrides = {}
    if a.group_map and a.group_map.exists():
        for line in a.group_map.read_text().splitlines():
            if not line.strip() or line.startswith("#"):
                continue
            cn, _, grp = line.partition("\t")
            overrides[cn.strip()] = grp.strip()

    items, skipped = scan(a.src)
    if not items:
        print("no certificates found")
        return 1
    for path, why in skipped:
        print(f"skipped {path}: {why}", file=sys.stderr)
    if not a.out and not a.db:
        print("give --out (XML) and/or --db (vault)")
        return 1

    if a.out:
        a.out.parent.mkdir(parents=True, exist_ok=True)
        a.out.write_text(build_xml(items, a.root_group, overrides, a.chain))

    if a.db:
        if a.no_password and (a.password_file or a.native_prompt):
            print(
                "--no-password cannot be combined with --password-file or "
                "--native-prompt",
                file=sys.stderr,
            )
            return 1
        if a.password_file and a.native_prompt:
            print(
                "--password-file cannot be combined with --native-prompt",
                file=sys.stderr,
            )
            return 1
        if a.no_password:
            pw, native = None, False
        elif a.native_prompt:
            pw, native = None, True
        elif a.password_file:
            if not a.password_file.is_file():
                print(f"no such password file: {a.password_file}", file=sys.stderr)
                return 1
            pw, native = a.password_file.read_text().rstrip("\r\n"), False
        else:
            pw, native = getpass.getpass(f"password for {a.db.name}: "), False
        if a.db.exists() and not a.dry_run:
            stamp = datetime.now().strftime("%Y%m%d-%H%M%S")
            backup = a.db.with_suffix(a.db.suffix + f".bak-{stamp}")
            shutil.copy2(a.db, backup)
            print(f"backup: {backup}")
        return write_db(
            a.db,
            items,
            overrides,
            a.chain,
            a.root_group,
            a.key_file,
            pw,
            native,
            a.dry_run,
        )

    roles = classify(items)
    rows = []
    for it in items:
        grp = group_for(it, overrides, roles)
        rows.append(
            "\t".join(
                [
                    f"{grp}/{it.title or it.cn}",
                    it.cn,
                    format(it.cert.serial_number, "X"),
                    f"{na_utc(it.cert):%Y-%m-%d}",
                    "yes" if it.key_pem else "NO-KEY",
                    it.fingerprint,
                    str(it.path),
                ]
            )
        )
    mpath = a.manifest or a.out.with_suffix(".manifest.tsv")
    mpath.write_text(
        "entry_path\tsubject_cn\tserial\tnot_after\thas_key\tsha256_fingerprint\tsource\n"
        + "\n".join(rows)
        + "\n"
    )

    certs = len(items)
    keys = sum(1 for i in items if i.key_pem)
    orphans = certs - keys
    print(
        f"parsed {certs} certificates, {keys} with matching private keys"
        + (f", {orphans} without" if orphans else "")
    )
    for r in sorted(rows):
        print(
            "  ",
            r.split("\t")[0][:38].ljust(38),
            r.split("\t")[1][:40].ljust(40),
            r.split("\t")[3].rjust(10),
            r.split("\t")[4],
        )
    print(f"\nwrote {a.out} ({a.out.stat().st_size} bytes) and {mpath}")
    if not a.dry_run:
        print(
            "\nnow run:\n  keepassxc-cli import "
            f"--set-key-file <keyfile> {a.out} <database>.kdbx"
        )
    return 0


if __name__ == "__main__":
    sys.exit(main())
