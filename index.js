const fs = require("fs");
const path = require("path");
const crypto = require("crypto");
const forge = require("node-forge");

function hashSHA256Sync(filePath) {
  try {
    const fileBuffer = fs.readFileSync(filePath);

    // Membuat hash SHA-256 dari konten file
    const hash = crypto.createHash("sha256");
    hash.update(fileBuffer);

    // Mengubah hasil hash menjadi string heksadesimal
    const hashHex = hash.digest("hex");

    console.log(`Hash SHA-256 dari file '${filePath}' adalah: ${hashHex}`);
    return hashHex;
  } catch (error) {
    console.error("Error saat membaca file:", error);
  }
}

function encryptKeyWithRSA(message, publicKey) {
  const encryptedKey = publicKey.encrypt(message, "RSA-OAEP");
  return forge.util.encode64(encryptedKey);
}

function decryptKeyWithRSA(encryptedKey, privateKey) {
  const decodedKey = forge.util.decode64(encryptedKey);
  const decryptedKey = privateKey.decrypt(decodedKey, "RSA-OAEP");
  return decryptedKey;
}

function generateRSAKeyPair() {
  const keypair = forge.pki.rsa.generateKeyPair({ bits: 2048 });
  return keypair;
}

function generateKeyPair() {
  const { publicKey, privateKey } = generateRSAKeyPair();
  fs.writeFileSync(
    path.join(__dirname, "/resources/public.pem"),
    forge.pki.publicKeyToPem(publicKey)
  );
  fs.writeFileSync(
    path.join(__dirname, "/resources/private.pem"),
    forge.pki.privateKeyToPem(privateKey)
  );
  console.log("berhasil buat keypair");
  return { publicKey, privateKey };
}

// const { publicKey, privateKey } = generateKeyPair();
const publickeyPath = fs.readFileSync(
  path.join(__dirname, "/resources/public.pem"),
  { encoding: "utf8" }
);
const publicKey = forge.pki.publicKeyFromPem(publickeyPath);
const privateKeyPath = fs.readFileSync(
  path.join(__dirname, "/resources/private.pem"),
  { encoding: "utf8" }
);
const privateKey = forge.pki.privateKeyFromPem(privateKeyPath);
const filePath = path.join(__dirname, "/resources/file.pdf");
// Ganti 'path/to/your/file.pdf' dengan path file yang ingin di-hash
function main() {
  const hashFile = hashSHA256Sync(filePath);
  const encryptedKey = encryptKeyWithRSA(hashFile, publicKey);
  console.log("\nEncrypted Key:", encryptedKey);
  const decryptedKey = decryptKeyWithRSA(encryptedKey, privateKey);
  console.log("\nDecrypted Key:", decryptedKey);

  if (
    decryptKeyWithRSA(encryptedKey, privateKey) ==
    "6f2d40e210cc55460caa67e44d80ed5aa4d7c424ab1bbb1e704d88836ad58c33"
  ) {
    console.log("sama");
  } else {
    console.log("tidak sama");
  }
}
main();
