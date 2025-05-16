import express from 'express';
import dotenv from 'dotenv';
import forge from 'node-forge';
import JSZip from 'jszip';
import fetch from 'node-fetch';
import fs from 'fs';

dotenv.config();
const app = express();
app.use(express.json());

function getFirstBagOfType(p12, bagType) {
  const result = p12.getBags({ bagType });
  const bags = result?.[bagType];
  if (Array.isArray(bags) && bags.length > 0) {
    return bags[0];
  }
  return null;
}

function signWithForge(manifest, p12Base64, password) {
  console.log("🔍 Extracting bags from P12...");
  const binary = Buffer.from(p12Base64, 'base64').toString('binary');
  const asn1 = forge.asn1.fromDer(forge.util.createBuffer(binary));
  const p12 = forge.pkcs12.pkcs12FromAsn1(asn1, password);

  const certBag = getFirstBagOfType(p12, forge.pki.oids.certBag);
  const keyBag = getFirstBagOfType(p12, forge.pki.oids.keyBag) ||
                 getFirstBagOfType(p12, forge.pki.oids.pkcs8ShroudedKeyBag);

  const cert = certBag?.cert;
  const key = keyBag?.key;

  if (!cert || !key) {
    console.error("🛑 Missing cert or key in parsed bags.");
    throw new Error("Missing cert or key");
  }

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

    console.log("ENV length:", p12Base64?.length);
console.log("ENV preview:", p12Base64?.slice(0, 100));
    
    const iconUrl = process.env.PASSKIT_ICON_URL || 'https://qlxnmbgtohaiyhbzfvvc.supabase.co/storage/v1/object/public/passkitfiles/icon.png';

    const signature = signWithForge(manifest, p12Base64, password);

    const iconRes = await fetch(iconUrl);
    if (!iconRes.ok) throw new Error('Failed to fetch icon');
    const iconBuffer = Buffer.from(await iconRes.arrayBuffer());

    const passJson = {
      description: "Vehicle Service Pass",
      formatVersion: 1,
      organizationName: "SHFT",
      passTypeIdentifier: "pass.com.shft.cardocs",
      serialNumber: plate,
      teamIdentifier: "V7AFS9KVXW", // Replace this with your actual Apple Developer Team ID
      backgroundColor: "rgb(255,255,255)",
      labelColor: "rgb(0,0,0)",
      foregroundColor: "rgb(0,0,0)",
      generic: {
        primaryFields: [
          {
            key: "vehicle",
            label: "Vehicle",
            value: `${year} ${make} ${model}`
          }
        ],
        auxiliaryFields: [
          {
            key: "plate",
            label: "License Plate",
            value: plate
          }
        ]
      }
    };

    const zip = new JSZip();
    zip.file('manifest.json', Buffer.from(manifest));
    zip.file('signature', Buffer.from(signature));
    zip.file('icon.png', iconBuffer);
    zip.file('pass.json', JSON.stringify(passJson, null, 2));

    console.log("manifest:", manifest);
console.log("signature length:", signature?.length);
console.log("iconBuffer length:", iconBuffer?.length || iconBuffer?.byteLength);
console.log("pass.json preview:", JSON.stringify(passJson).substring(0, 100));

    const pkpass = await zip.generateAsync({ type: 'nodebuffer' });
    console.log("Generated pkpass buffer size:", pkpass.length);

    // Optional: Save locally for testing
    //fs.writeFileSync('mycar.pkpass', pkpass);

    res.setHeader('Content-Type', 'application/vnd.apple.pkpass');
    res.setHeader('Content-Disposition', 'attachment; filename=mycar.pkpass');
    res.send(pkpass);
  } catch (err) {
    console.error('GENERATION ERROR:', err);
    res.status(500).json({ error: err.message });
  }
});

const PORT = process.env.PORT || 10000;
app.listen(PORT, () => {
  console.log(`✅ Server running on http://localhost:${PORT}`);
});
