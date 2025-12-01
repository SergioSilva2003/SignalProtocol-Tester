import binascii
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

# 1. Cola aqui a 'Nova CHAIN KEY' que apareceu no terminal
CHAIN_KEY_HEX = "27447b74f9b5b97e39dea209b9d0fd295f01209692dbba5f6c37cfe9b8742140"

# 2. Cola aqui o Payload da mensagem
PAYLOAD_HEX = "d5a2aa9a2ca6939851883b71873e1deb41f5c938c6d1865bd85f0d9f5f336935b8915adce99de7467c094a90a17c4bfbcd18c6d7fc23fa97bbf94df6e9f674e395e4f339749b62dc413ffc46e4b39edff3ea4ec0fc6ab2d9"


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



