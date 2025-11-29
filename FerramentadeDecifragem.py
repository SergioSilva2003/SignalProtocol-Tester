import binascii
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

# ================= CONFIGURAÇÃO =================
# 1. Cola aqui a 'Nova CHAIN KEY' que apareceu no terminal
CHAIN_KEY_HEX = "0420064f5ea27b42c34b8aec6384f00893a9e06bb0b30b6e8c02284d06686229"

# 2. Cola aqui o Payload da mensagem
PAYLOAD_HEX = "a0773d4694cf36f4ff5376164e3add9809892444a043c38184291d9ad7f5ba52ecf97f187d0d8125d7907e820210cc09c3a41547701d5185172b4673de3afeac7c9fbd31239219af9ae52db91bb6ccfbd17435a76499e688694ee63f"
# ================================================

def derive(material, info):
    hkdf = HKDF(
        algorithm=hashes.SHA256(), length=32, salt=None, info=info, backend=default_backend()
    )
    return hkdf.derive(material)

def main():
    try:
        chain_key = binascii.unhexlify(CHAIN_KEY_HEX)
        dados = binascii.unhexlify(PAYLOAD_HEX.replace(':', '').replace(' ', ''))
        
        nonce = dados[32:44]
        ciphertext = dados[44:]
        
        print(f"--- DECIFRADOR (Baseado em Chain Key) ---")

        # Tenta decifrar as próximas 3 mensagens desta corrente
        for i in range(1, 4):
            print(f"\n[Tentativa {i}]")
            
            # 1. Derivar Message Key
            msg_key = derive(chain_key, b"chave-mensagem")
            print(f" -> Msg Key: {msg_key.hex()[:10]}...")
            
            # 2. Avançar a Chain Key (para a próxima volta)
            next_chain = derive(chain_key, b"proxima-chain-key")
            
            # 3. Tentar Decifrar
            try:
                aes = AESGCM(msg_key)
                texto = aes.decrypt(nonce, ciphertext, None).decode('utf-8')
                print(f">>> SUCESSO: '{texto}'")
                return
            except:
                print(" -> Falhou. Avançando corrente...")
                chain_key = next_chain

    except Exception as e:
        print(f"Erro: {e}")

if __name__ == "__main__":
    main()