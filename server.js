import express from 'express';
import dotenv from 'dotenv';
import forge from 'node-forge';
import JSZip from 'jszip';
import { readFile } from 'fs/promises';
import crypto from 'crypto';

dotenv.config();

const app = express();
app.use(express.json());

function generateManifest(files) {
  const manifest = {};
  for (const [filename, buffer] of Object.entries(files)) {
    const hash = crypto.createHash('sha1').update(buffer).digest('hex');
    manifest[filename] = hash;
  }
  return manifest;
}

function signWithForge(manifest, p12Base64, password) {
  const binary = Buffer.from(p12Base64, 'base64').toString('binary');
  const asn1 = forge.asn1.fromDer(forge.util.createBuffer(binary));
  const p12 = forge.pkcs12.pkcs12FromAsn1(asn1, password);

  const certBag = p12.getBags({ bagType: forge.pki.oids.certBag })?.[forge.pki.oids.certBag]?.[0];
  const keyBag = p12.getBags({ bagType: forge.pki.oids.keyBag })?.[forge.pki.oids.keyBag]?.[0] ||
    p12.getBags({ bagType: forge.pki.oids.pkcs8ShroudedKeyBag })?.[forge.pki.oids.pkcs8ShroudedKeyBag]?.[0];

  const cert = certBag?.cert;
  const key = keyBag?.key;

  if (!cert || !key) {
    throw new Error('Missing cert or key');
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
    const { make, model, year, plate, fuelType, transmission, bodyType, driveTrain, engine, finalReview, vinNum, logoUrl } = req.body;

    const headerFields = [];
    const auxiliaryFields = [];
    const backFields = [];

    if (make || model || year) {
      headerFields.push({ key: 'vehicle', label: 'Vehicle', value: `${year || ''} ${make || ''} ${model || ''}`.trim() });
    }
    if (transmission) auxiliaryFields.push({ key: 'transmission', label: 'Transmission', value: transmission });
    if (fuelType) auxiliaryFields.push({ key: 'fuel', label: 'Fuel Type', value: fuelType });
    if (plate) auxiliaryFields.push({ key: 'plate', label: 'License Plate', value: plate });
    if (bodyType) auxiliaryFields.push({ key: 'body', label: 'Body Type', value: bodyType });

    if (driveTrain) backFields.push({ key: 'drive', label: 'Drivetrain', value: driveTrain });
    if (engine) backFields.push({ key: 'engine', label: 'Engine Size', value: engine });
    if (finalReview) backFields.push({ key: 'review', label: 'Market Review', value: finalReview });
    if (vinNum) backFields.push({ key: 'vin', label: 'VIN', value: vinNum });

    const passData = {
      description: "Vehicle Service Pass",
      formatVersion: 1,
      organizationName: "SHFT",
      passTypeIdentifier: "pass.com.shft.cardocs",
      serialNumber: vinNum,
      teamIdentifier: "V7AFS9KVXW",
      backgroundColor: "#ffffff",
      labelColor: "#01D046",
      foregroundColor: "#000000",
      sharingProhibited: true,
      logoText: "",
      logo: "logo.png",
      storeCard: {
        headerFields,
        auxiliaryFields,
        backFields
      }
    };

    const passJSON = Buffer.from(JSON.stringify(passData));

    const p12Base64 = process.env.PASSKIT_P12_BASE64;
    const password = process.env.PASSKIT_P12_PASSWORD || '';

    const iconBuffer = await readFile('./icon.png');
    const icon2xBuffer = await readFile('./icon@2x.png');
const stripBuffer = await readFile('./strip.png');
    //const thumbnailBuffer = await readFile('./thumbnail.png');
    
    let logoBuffer;
    if (logoUrl) {
      const logoRes = await fetch(logoUrl);
      if (!logoRes.ok) throw new Error('Failed to fetch dynamic logo from provided URL');
      logoBuffer = Buffer.from(await logoRes.arrayBuffer());
    } else {
      logoBuffer = await readFile('./logo.png');
    }

const fileBuffers = {
  'pass.json': passJSON,
  'icon.png': iconBuffer,
  'icon@2x.png': icon2xBuffer,
  'logo.png': logoBuffer,
  'strip.png': stripBuffer
  //'thumbnail.png': thumbnailBuffer
};

    const manifestObject = generateManifest(fileBuffers);
    const manifestJSON = Buffer.from(JSON.stringify(manifestObject));
    const signature = signWithForge(manifestJSON.toString(), p12Base64, password);

    const zip = new JSZip();
    zip.file('pass.json', passJSON);
    zip.file('manifest.json', manifestJSON);
    zip.file('signature', signature, { binary: true });
    zip.file('icon.png', iconBuffer);
    zip.file('icon@2x.png', icon2xBuffer);
    zip.file('logo.png', logoBuffer);
zip.file('strip.png', stripBuffer);
    //zip.file('thumbnail.png', thumbnailBuffer);

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
app.listen(PORT, () => console.log(`🚗 Wallet pass server running on port ${PORT}`));
