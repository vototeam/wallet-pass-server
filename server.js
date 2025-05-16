// server.js
import express from 'express';
import JSZip from 'jszip';
import forge from 'node-forge';
import dotenv from 'dotenv';
import fetch from 'node-fetch';

dotenv.config();

const app = express();
app.use(express.json());

function signWithForge(manifest, p12Base64, password) {
  const binary = Buffer.from(p12Base64, 'base64').toString('binary');
  const p12Asn1 = forge.asn1.fromDer(binary);
  const p12 = forge.pkcs12.pkcs12FromAsn1(p12Asn1, password);

  const certBags = p12.getBags({ bagType: forge.pki.oids.certBag })[forge.pki.oids.certBag] || [];
  const keyBags = p12.getBags({ bagType: forge.pki.oids.keyBag })[forge.pki.oids.keyBag] || [];
  const shroudedKeyBags = p12.getBags({ bagType: forge.pki.oids.pkcs8ShroudedKeyBag })[forge.pki.oids.pkcs8ShroudedKeyBag] || [];

  const cert = certBags[0]?.cert;
  const key = keyBags[0]?.key || shroudedKeyBags[0]?.key;

  if (!cert || !key) throw new Error('Certificate or private key not found in P12');

  const p7 = forge.pkcs7.createSignedData();
  p7.content = forge.util.createBuffer(manifest);
  p7.addCertificate(cert);
  p7.addSigner({
    key,
    certificate: cert,
    digestAlgorithm: forge.pki.oids.sha1,
    authenticatedAttributes: [
      { type: forge.pki.oids.contentType, value: forge.pki.oids.data },
      { type: forge.pki.oids.messageDigest },
      { type: forge.pki.oids.signingTime, value: new Date() },
    ],
  });

  const signature = forge.asn1.toDer(p7.toAsn1()).getBytes();
  return Buffer.from(signature, 'binary');
}

app.post('/generate-pass', async (req, res) => {
  try {
    const { make, model, year, plate } = req.body;
    if (!make || !model || !year || !plate) {
      return res.status(400).json({ error: 'Missing required fields' });
    }

    const manifest = JSON.stringify({ make, model, year, plate });
    const { PASSKIT_P12_BASE64, PASSKIT_P12_PASSWORD, PASSKIT_ICON_URL } = process.env;

    const signature = signWithForge(manifest, PASSKIT_P12_BASE64, PASSKIT_P12_PASSWORD || '');

    const zip = new JSZip();
    zip.file('manifest.json', manifest);
    zip.file('signature', signature);

    const iconUrl = PASSKIT_ICON_URL || 'https://qlxnmbgtohaiyhbzfvvc.supabase.co/storage/v1/object/public/passkitfiles/icon.png';
    const iconRes = await fetch(iconUrl);
    if (!iconRes.ok) throw new Error(`Failed to fetch icon (${iconRes.status})`);
    const iconBuffer = await iconRes.arrayBuffer();
    zip.file('icon.png', Buffer.from(iconBuffer));

    const pkpass = await zip.generateAsync({ type: 'nodebuffer' });
    res.setHeader('Content-Type', 'application/vnd.apple.pkpass');
    res.setHeader('Content-Disposition', 'attachment; filename=mycar.pkpass');
    res.send(pkpass);
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: err.message });
  }
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`Pass server running on port ${PORT}`));
