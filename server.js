import express from 'express';
import dotenv from 'dotenv';
import forge from 'node-forge';
import JSZip from 'jszip';
import fetch from 'node-fetch';

dotenv.config();

const app = express();
app.use(express.json());

function signWithForge(manifest, p12Base64, password) {
  const binary = Buffer.from(p12Base64, 'base64').toString('binary');
  const asn1 = forge.asn1.fromDer(forge.util.createBuffer(binary));
  const p12 = forge.pkcs12.pkcs12FromAsn1(asn1, password);

  const certBags = p12.getBags({ bagType: forge.pki.oids.certBag }).certBags;
  const keyBags = p12.getBags({ bagType: forge.pki.oids.keyBag }).keyBags;
  const shroudedBags = p12.getBags({ bagType: forge.pki.oids.pkcs8ShroudedKeyBag }).pkcs8ShroudedKeyBag;

  const cert = certBags?.[0]?.cert;
  const key = keyBags?.[0]?.key || shroudedBags?.[0]?.key;

  if (!cert || !key) throw new Error('Missing cert or key');

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

  return Buffer.from(forge.asn1.toDer(p7.toAsn1()).getBytes(), 'binary');
}

app.post('/generate', async (req, res) => {
  try {
    const { make, model, year, plate } = req.body;
    const manifest = JSON.stringify({ make, model, year, plate });

    const p12Base64 = process.env.PASSKIT_P12_BASE64;
    const password = process.env.PASSKIT_P12_PASSWORD || '';
    const iconUrl = process.env.PASSKIT_ICON_URL || 'https://qlxnmbgtohaiyhbzfvvc.supabase.co/storage/v1/object/public/passkitfiles/icon.png';

    const signature = signWithForge(manifest, p12Base64, password);

    const iconRes = await fetch(iconUrl);
    if (!iconRes.ok) throw new Error('Failed to fetch icon');
    const iconBuffer = await iconRes.arrayBuffer();

    const zip = new JSZip();
    zip.file('manifest.json', manifest);
    zip.file('signature', signature, { binary: true });
    zip.file('icon.png', iconBuffer);

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
app.listen(PORT, () => console.log(`Server running on port ${PORT}`));
