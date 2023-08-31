from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
from cryptography.exceptions import InvalidKey, InvalidTag
from ed25519 import BadSignatureError
import machineid
import argparse
import ed25519
import base64
import json
import sys
import os

parser = argparse.ArgumentParser()

parser.add_argument('-p', '--path', dest='path', required=True, help='Path to machine file (required)')
parser.add_argument('-l', '--license', dest='license', required=True, help='License key (required)')
parser.add_argument('-f', '--fingerprint', dest='fingerprint', default=machineid.hashed_id('example-app'), help='Machine fingerprint')

args = parser.parse_args()

# Read the machine file
machine_file = None

try:
  with open(args.path) as f:
    machine_file = f.read()
except (FileNotFoundError, PermissionError):
  print('[error] path does not exist! (or permission was denied)')

  sys.exit(1)

# Strip the header and footer from the machine file certificate
payload = machine_file.removeprefix('-----BEGIN MACHINE FILE-----\n') \
                      .removesuffix('-----END MACHINE FILE-----\n')

# Decode the payload and parse the JSON object
data = json.loads(base64.b64decode(payload))

# Retrieve the enc and sig properties
enc = data['enc']
sig = data['sig']
alg = data['alg']

if alg != 'aes-256-gcm+ed25519':
  print('[error] algorithm is not supported!')

  sys.exit(1)

# Verify using Ed25519
try:
  verify_key = ed25519.VerifyingKey(
    os.environ['KEYGEN_PUBLIC_KEY'].encode(),
    encoding='hex',
  )

  verify_key.verify(
    base64.b64decode(sig),
    ('machine/%s' % enc).encode(),
  )
except (AssertionError, BadSignatureError):
  print('[error] verification failed!')

  sys.exit(1)

print('[info] verification successful!')

# Hash the license key and fingerprint using SHA256
digest = hashes.Hash(hashes.SHA256(), default_backend())
digest.update(args.license.encode())
digest.update(args.fingerprint.encode())
key = digest.finalize()

# Split and decode the enc value
ciphertext, iv, tag = map(
  lambda p: base64.b64decode(p),
  enc.split('.'),
)

# Decrypt ciphertext
try:
  aes = Cipher(
    algorithms.AES(key),
    modes.GCM(iv, None, len(tag)),
    default_backend(),
  )
  dec = aes.decryptor()

  plaintext = dec.update(ciphertext) + \
              dec.finalize_with_tag(tag)
except (InvalidKey, InvalidTag):
  print('[error] decryption failed!')

  sys.exit(1)

print('[info] decryption successful!')
print(
  json.dumps(json.loads(plaintext.decode()), indent=2)
)
