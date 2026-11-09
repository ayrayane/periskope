"""Feed parsing and trust, without a database."""
import datetime
import gzip
import ssl

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID
from periskope_scheduler import feeds


def private_ca(path):
    key = ec.generate_private_key(ec.SECP256R1())
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Periskope test CA")])
    now = datetime.datetime.now(datetime.UTC)
    cert = (x509.CertificateBuilder().subject_name(name).issuer_name(name).public_key(key.public_key())
            .serial_number(1).not_valid_before(now).not_valid_after(now + datetime.timedelta(days=1))
            .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True).sign(key, hashes.SHA256()))
    path.write_bytes(cert.public_bytes(serialization.Encoding.PEM))


def test_private_ca_adds_to_public_authorities(tmp_path, monkeypatch):
    """A platform CA (oidc.caConfigMap) must not replace the public ones: official sites and Nexus both verify."""
    monkeypatch.delenv("SSL_CERT_FILE", raising=False)
    public = len(feeds.trust().get_ca_certs())
    private_ca(tmp_path / "ca.crt")
    monkeypatch.setenv("SSL_CERT_FILE", str(tmp_path / "ca.crt"))
    ctx = feeds.trust()
    subjects = [dict(x[0] for x in c["subject"]).get("commonName") for c in ctx.get_ca_certs()]
    assert "Periskope test CA" in subjects and len(subjects) == public + 1 and ctx.verify_mode == ssl.CERT_REQUIRED


def test_epss_plain_or_gzipped():
    raw = b"#model_version:v1,score_date:2026-11-08T00:00:00+0000\ncve,epss,percentile\ncve-2024-1,0.5,0.9\n"
    for body in (raw, gzip.compress(raw)):
        assert feeds.parse_epss(body) == ([("CVE-2024-1", 0.5, 0.9)], "2026-11-08T00:00:00+0000")
