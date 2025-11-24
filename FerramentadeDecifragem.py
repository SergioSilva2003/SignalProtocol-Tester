import os
from cryptography.hazmat.primitives.asymmetric import x25519
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

# --- FUNÇÕES DE UTILIDADE ---
def derive_key(input_material, info):
    hkdf = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=None,
        info=info,
        backend=default_backend()
    )
    return hkdf.derive(input_material)

def decrypt_manual(sk_hex, ciphertext_hex, is_alice_sender=True):
    print(f"--- A TENTAR DECIFRAR ---")
    
    # 1. Converter o SK (Segredo Partilhado) de Hex para Bytes
    root_key = bytes.fromhex(sk_hex)
    
    # 2. Converter o Payload do Wireshark de Hex para Bytes
    # (Remova espaços ou dois pontos se houver)
    ciphertext_completo = bytes.fromhex(ciphertext_hex.replace(':', '').replace(' ', ''))
    
    # 3. Separar as partes do pacote
    # Estrutura: [32 bytes PubKey DH] + [12 bytes Nonce] + [Ciphertext + Tag]
    try:
        public_key_bytes = ciphertext_completo[:32]
        nonce = ciphertext_completo[32:44]
        ciphertext_real = ciphertext_completo[44:]
    except IndexError:
        print("Erro: O texto cifrado é demasiado curto.")
        return

    print(f"Nonce detetado: {nonce.hex()}")
    
    # 4. Derivar as chaves iniciais a partir do SK
    # A Alice usa a chain de envio inicial baseada no SK.
    # O Bob usa a chain de receção inicial baseada no SK.
    # A info DEVE ser igual à usada no script original: b"primeira-chain-key"
    
    chain_key = derive_key(root_key, b"primeira-chain-key")
    
    # 5. Derivar a Chave da Mensagem (Message Key)
    # No Double Ratchet, a chain key avança um passo para gerar a message key
    message_key = derive_key(chain_key, b"chave-mensagem")
    
    print(f"Message Key calculada: {message_key.hex()}")
    
    # 6. Tentar Decifrar com AES-GCM
    try:
        aesgcm = AESGCM(message_key)
        plaintext_bytes = aesgcm.decrypt(nonce, ciphertext_real, None)
        print(f"\nSUCESSO! Mensagem Original: \n>> '{plaintext_bytes.decode('utf-8')}' <<")
    except Exception as e:
        print(f"\nFALHA: Não foi possível decifrar. Motivos possíveis:")
        print("1. O SK está errado.")
        print("2. Esta não é a primeira mensagem (a catraca já rodou).")
        print("3. O texto cifrado foi copiado incorretamente do Wireshark.")
        print(f"Erro técnico: {e}")

if __name__ == "__main__":
    # ================= CONFIGURAÇÃO =================
    
    # 1. COLE AQUI O SK (DO SEU LOG DO PYTHON)
    # Exemplo: sk_input = "25a7c9b263979dbc99cefb5435c24e6a1fd68ccf8ad5d3f3fbdda90e4946d9ea"
    MEU_SK = "F19EF6B457DDCC0B710462449DC84763E2C536B9F9BE533C6159AB7A0DA63983" 
    
    # 2. COLE AQUI O PAYLOAD DO WIRESHARK (Data)
    # Clique direito no pacote "PSH, ACK" da msg cifrada -> Copy -> Bytes as Hex Stream
    PAYLOAD_WIRESHARK = "f92c7d3a2b4b2c52e954145704de01bb8c74ef3a644cebc4981d6e087584034ef28ab8ee2b312aadbe7e015bcbdb129db4c427c28e9c122eb9e54918bb13a0139714f9877710d2d6bcb48dc00ff457599ffa9ede9d7166976a14f004"
    
    # ================================================
    
    if MEU_SK == "COLE_SEU_SK_AQUI":
        print("Por favor, edite o script e coloque o seu SK e o Payload do Wireshark.")
    else:
        decrypt_manual(MEU_SK, PAYLOAD_WIRESHARK)