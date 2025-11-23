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
    MEU_SK = "7edd7da27e48effc5ce7ac23e875229007e9698a2b35d9053f190137fe47ffd5" 
    
    # 2. COLE AQUI O PAYLOAD DO WIRESHARK (Data)
    # Clique direito no pacote "PSH, ACK" da msg cifrada -> Copy -> Bytes as Hex Stream
    PAYLOAD_WIRESHARK = "d14330246e93e51aa5102db4f88ffed479dc12a763bd33ca9b03a049c332f9187978024d4706a75f6dd8b6e8de39c3137215820ef875109f7c230d036aa5d84159da4c101e1abb0a27118bf209ab30779413650bef04ae"
    
    # ================================================
    
    if MEU_SK == "COLE_SEU_SK_AQUI":
        print("Por favor, edite o script e coloque o seu SK e o Payload do Wireshark.")
    else:
        decrypt_manual(MEU_SK, PAYLOAD_WIRESHARK)