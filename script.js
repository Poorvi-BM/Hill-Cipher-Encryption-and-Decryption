// script.js - Hill Cipher (tested, no syntax errors)

// modular inverse (brute force, mod small 26)
function modInverse(a, m) {
  a = ((a % m) + m) % m;
  for (let x = 1; x < m; x++) {
    if ((a * x) % m === 1) return x;
  }
  return null;
}

// convert a key string to n x n matrix (row-major)
function textToMatrix(text, n) {
  let vals = text.toUpperCase().replace(/[^A-Z]/g, '').split('').map(c => c.charCodeAt(0) - 65);
  while (vals.length < n * n) vals.push(23); // pad with 'X' (23)
  let m = [];
  for (let i = 0; i < n; i++) {
    m.push(vals.slice(i * n, i * n + n));
  }
  return m;
}

// determinant for 2x2 or 3x3
function determinant(mat) {
  const n = mat.length;
  if (n === 2) {
    return mat[0][0] * mat[1][1] - mat[0][1] * mat[1][0];
  } else if (n === 3) {
    const a = mat;
    return (
      a[0][0] * (a[1][1] * a[2][2] - a[1][2] * a[2][1]) -
      a[0][1] * (a[1][0] * a[2][2] - a[1][2] * a[2][0]) +
      a[0][2] * (a[1][0] * a[2][1] - a[1][1] * a[2][0])
    );
  }
  return 0;
}

// adjugate for 2x2 or 3x3
function adjugate(mat) {
  const n = mat.length;
  if (n === 2) {
    return [
      [mat[1][1], -mat[0][1]],
      [-mat[1][0], mat[0][0]]
    ];
  } else if (n === 3) {
    const a = mat;
    const cof = [
      [
        (a[1][1] * a[2][2] - a[1][2] * a[2][1]),
        -(a[1][0] * a[2][2] - a[1][2] * a[2][0]),
        (a[1][0] * a[2][1] - a[1][1] * a[2][0])
      ],
      [
        -(a[0][1] * a[2][2] - a[0][2] * a[2][1]),
        (a[0][0] * a[2][2] - a[0][2] * a[2][0]),
        -(a[0][0] * a[2][1] - a[0][1] * a[2][0])
      ],
      [
        (a[0][1] * a[1][2] - a[0][2] * a[1][1]),
        -(a[0][0] * a[1][2] - a[0][2] * a[1][0]),
        (a[0][0] * a[1][1] - a[0][1] * a[1][0])
      ]
    ];
    // transpose cof to get adjugate
    const adj = [[], [], []];
    for (let i = 0; i < 3; i++) {
      for (let j = 0; j < 3; j++) adj[i][j] = cof[j][i];
    }
    return adj;
  }
  return null;
}

// invert matrix modulo 26
function invertMatrixMod(mat, mod) {
  const det = determinant(mat);
  const detMod = ((det % mod) + mod) % mod;
  const invDet = modInverse(detMod, mod);
  if (invDet === null) return null;
  const adj = adjugate(mat);
  const n = mat.length;
  const inv = [];
  for (let i = 0; i < n; i++) {
    inv[i] = [];
    for (let j = 0; j < n; j++) {
      inv[i][j] = ((adj[i][j] * invDet) % mod + mod) % mod;
    }
  }
  return inv;
}

// multiply matrix (n x n) with vector (n x 1)
function matMulVec(mat, vec) {
  const n = mat.length;
  const res = new Array(n).fill(0);
  for (let i = 0; i < n; i++) {
    let s = 0;
    for (let j = 0; j < n; j++) s += mat[i][j] * vec[j];
    res[i] = ((s % 26) + 26) % 26;
  }
  return res;
}

/* --- main UI functions --- */

function encrypt() {
  const n = parseInt(document.getElementById('matrixSize').value, 10);
  const key = document.getElementById('keyInput').value.toUpperCase().replace(/[^A-Z]/g, '');
  const plain = document.getElementById('plaintext').value.toUpperCase().replace(/[^A-Z]/g, '');

  if (key.length !== n * n) {
    alert(`Key must be ${n * n} letters`);
    return;
  }
  if (!plain) {
    alert('Enter plaintext');
    return;
  }

  const keyMat = textToMatrix(key, n);
  const det = determinant(keyMat);
  const detMod = ((det % 26) + 26) % 26;
  if (modInverse(detMod, 26) === null) {
    alert('Key matrix is not invertible modulo 26. Use Generate Key or a different key.');
    return;
  }

  let vals = plain.split('').map(c => c.charCodeAt(0) - 65);
  while (vals.length % n !== 0) vals.push(23); // pad with X

  let cipher = '';
  for (let i = 0; i < vals.length; i += n) {
    const block = vals.slice(i, i + n);
    const out = matMulVec(keyMat, block);
    cipher += out.map(x => String.fromCharCode(x + 65)).join('');
  }

  document.getElementById('cipherText').textContent = cipher;
  document.getElementById('plainOut').textContent = '';
  document.getElementById('details').textContent =
    `Encrypted using ${n}×${n} key matrix (det=${det}, det mod26=${detMod})`;
}

function decrypt() {
  const n = parseInt(document.getElementById('matrixSize').value, 10);
  const key = document.getElementById('keyInput').value.toUpperCase().replace(/[^A-Z]/g, '');
  const cipher = document.getElementById('cipherText').textContent.toUpperCase().replace(/[^A-Z]/g, '');

  if (key.length !== n * n) {
    alert(`Key must be ${n * n} letters`);
    return;
  }
  if (!cipher) {
    alert('No ciphertext found (encrypt first or paste ciphertext into the field).');
    return;
  }

  const keyMat = textToMatrix(key, n);
  const invKey = invertMatrixMod(keyMat, 26);
  if (invKey === null) {
    alert('Key matrix not invertible modulo 26. Cannot decrypt.');
    return;
  }

  const vals = cipher.split('').map(c => c.charCodeAt(0) - 65);
  let plain = '';
  for (let i = 0; i < vals.length; i += n) {
    const block = vals.slice(i, i + n);
    const out = matMulVec(invKey, block);
    plain += out.map(x => String.fromCharCode(x + 65)).join('');
  }

  document.getElementById('plainOut').textContent = plain;
  document.getElementById('details').textContent = 'Decrypted using inverse key matrix (mod 26)';
}

function generateKey() {
  const n = parseInt(document.getElementById('matrixSize').value, 10);
  let key;
  while (true) {
    key = Array(n * n)
      .fill(0)
      .map(() => String.fromCharCode(65 + Math.floor(Math.random() * 26)))
      .join('');
    const mat = textToMatrix(key, n);
    const detMod = ((determinant(mat) % 26) + 26) % 26;
    if (modInverse(detMod, 26) !== null) break; // invertible
  }
  document.getElementById('keyInput').value = key;
  document.getElementById('details').textContent = `Generated invertible ${n}×${n} key matrix`;
}

/* wire up buttons (IDs must match index.html) */
document.getElementById('genBtn').addEventListener('click', generateKey);
document.getElementById('encBtn').addEventListener('click', encrypt);
document.getElementById('decBtn').addEventListener('click', decrypt);