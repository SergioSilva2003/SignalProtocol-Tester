# (Importações e Classes Participante/SessaoSegura mantêm-se iguais)
# Apenas a lógica de loop e tratamento de exceções no __main__ foi melhorada.

import socket
import os
from cryptography.hazmat.primitives.asymmetric import x25519
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

# --- 2. Funções Auxiliares ---

def generate_x25519_keys():
    private_key = x25519.X25519PrivateKey.generate()
    public_key = private_key.public_key()
    return private_key, public_key

def derive_key(input_material, info):
    hkdf = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=None,
        info=info,
        backend=default_backend()
    )
    return hkdf.derive(input_material)

# --- 3. Classe Participante ---

class Participante:
    def __init__(self, nome):
        self.nome = nome
        print(f"[{self.nome}] A gerar chaves...")
        self.ik_private, self.ik_public = generate_x25519_keys()
        self.spk_private, self.spk_public = generate_x25519_keys()
        self.opk_private, self.opk_public = generate_x25519_keys()

    def gerar_bundle_publico(self):
        return {
            'ik_publica': self.ik_public,
            'spk_publica': self.spk_public,
            'opk_publica': self.opk_public
        }

    def receber_sessao_x3dh(self, info_iniciador):
        print(f"[{self.nome}] A receber sessão X3DH...")
        ik_iniciador = info_iniciador['ik_publica_iniciador']
        ek_iniciador = info_iniciador['ek_publica_iniciador']

        dh1 = self.spk_private.exchange(ik_iniciador)
        dh2 = self.ik_private.exchange(ek_iniciador)
        dh3 = self.spk_private.exchange(ek_iniciador)
        dh4 = self.opk_private.exchange(ek_iniciador)
        
        ikm = dh1 + dh2 + dh3 + dh4
        sk = derive_key(ikm, info=b'x3dh-shared-secret')
        print(f"[{self.nome}] SK calculado: {sk.hex()}")
        return sk

# --- 4. Classe SessaoSegura (CORRIGIDA) ---

class SessaoSegura:
    def __init__(self, sk_inicial, iniciador=False):
        print(f"\n[SessaoSegura] Sessão iniciada com SK.")
        self.root_key = sk_inicial 
        self.sou_iniciador = iniciador
        self.sessao_inicializada = False
        
        self.dh_ratchet_private, self.dh_ratchet_public = generate_x25519_keys()
        self.other_party_dh_public = None 
        
        if iniciador:
            self.chain_key_send = self.derivar(self.root_key, b"primeira-chain-key")
            self.chain_key_recv = None 
        else:
            self.chain_key_send = None 
            self.chain_key_recv = self.derivar(self.root_key, b"primeira-chain-key")

    def derivar(self, chave_material, info_contextual):
        hkdf = HKDF(
            algorithm=hashes.SHA256(),
            length=32,
            salt=None,
            info=info_contextual,
            backend=default_backend()
        )
        return hkdf.derive(chave_material)

    def _avancar_catraca_simetrica(self, chain_key):
        if chain_key is None:
            raise Exception("Catraca simétrica não inicializada.")
        message_key = self.derivar(chain_key, b"chave-mensagem")
        next_chain_key = self.derivar(chain_key, b"proxima-chain-key")
        return message_key, next_chain_key

    def _avancar_catraca_assimetrica(self, other_party_public_key, chain_para_atualizar):
        print(f"[SessaoSegura] A avançar catraca DH para obter chain de {chain_para_atualizar.upper()}...")
        dh_secret = self.dh_ratchet_private.exchange(other_party_public_key)
        
        nova_root_key_input = self.root_key + dh_secret
        self.root_key = self.derivar(nova_root_key_input, b"nova-root-key")
        nova_chain_key = self.derivar(self.root_key, b"nova-chain-key")
        
        if chain_para_atualizar == "send":
            self.chain_key_send = nova_chain_key
            # NÃO rodamos a chave aqui. Mantemos a chave atual para o envio.
        elif chain_para_atualizar == "recv":
            self.chain_key_recv = nova_chain_key
            # AQUI sim, rodamos a chave para o futuro passo de envio.
            self.dh_ratchet_private, self.dh_ratchet_public = generate_x25519_keys()

    def cifrar(self, plaintext_str):
        if self.other_party_dh_public:
            print("[SessaoSegura] Chave DH do outro detetada. Atualizando chain de ENVIO.")
            self._avancar_catraca_assimetrica(self.other_party_dh_public, "send")
            self.other_party_dh_public = None 
        
        message_key, next_chain_key = self._avancar_catraca_simetrica(self.chain_key_send)
        self.chain_key_send = next_chain_key
        
        aesgcm = AESGCM(message_key)
        nonce = os.urandom(12)
        ciphertext = aesgcm.encrypt(nonce, plaintext_str.encode('utf-8'), None)
        
        public_key_bytes = self.dh_ratchet_public.public_bytes(
            serialization.Encoding.Raw, serialization.PublicFormat.Raw
        )
        return public_key_bytes + nonce + ciphertext
        
    def decifrar(self, ciphertext_completo):
        try:
            public_key_bytes = ciphertext_completo[:32]
            nonce = ciphertext_completo[32:44]
            ciphertext = ciphertext_completo[44:]
        except Exception:
            return None

        incoming_public_key = x25519.X25519PublicKey.from_public_bytes(public_key_bytes)
        
        if not self.sou_iniciador and not self.sessao_inicializada:
            print("[SessaoSegura] (Bob) 1ª Mensagem. Decifrar com chain X3DH, preparar Envio.")
            self.other_party_dh_public = incoming_public_key 
            
            try:
                message_key, next_chain_key = self._avancar_catraca_simetrica(self.chain_key_recv)
                aesgcm = AESGCM(message_key)
                plaintext = aesgcm.decrypt(nonce, ciphertext, None).decode('utf-8')
                self.chain_key_recv = next_chain_key

                self.dh_ratchet_private, self.dh_ratchet_public = generate_x25519_keys()
                dh_secret = self.dh_ratchet_private.exchange(incoming_public_key)
                
                nova_root_key_input = self.root_key + dh_secret
                self.root_key = self.derivar(nova_root_key_input, b"nova-root-key")
                self.chain_key_send = self.derivar(self.root_key, b"nova-chain-key")
                
                self.sessao_inicializada = True
                self.other_party_dh_public = None 
                
                return plaintext
            except Exception as e:
                print(f"[SessaoSegura] Falha ao decifrar msg inicial: {e}")
                return None

        if self.other_party_dh_public != incoming_public_key:
            print("[SessaoSegura] Chave DH nova. Atualizando chain de RECEÇÃO.")
            self._avancar_catraca_assimetrica(incoming_public_key, "recv")
            self.other_party_dh_public = incoming_public_key
        
        try:
            message_key, next_chain_key = self._avancar_catraca_simetrica(self.chain_key_recv)
            aesgcm = AESGCM(message_key)
            plaintext = aesgcm.decrypt(nonce, ciphertext, None).decode('utf-8')
            self.chain_key_recv = next_chain_key
            return plaintext
        except Exception as e:
            print(f"[SessaoSegura] Falha ao decifrar: {e}")
            return None

# --- 5. Bloco de Execução Principal (Bob) ---

if __name__ == "__main__":
    HOST = '127.0.0.1'
    PORT = 9999
    
    print("--- BOB (Servidor) ---")
    bob = Participante("Bob")
    bundle = bob.gerar_bundle_publico()
    
    b_bytes = b''.join([
        bundle['ik_publica'].public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw),
        bundle['spk_publica'].public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw),
        bundle['opk_publica'].public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    ])

    while True:
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                s.bind((HOST, PORT))
                s.listen()
                print(f"\n[Bob] A aguardar conexão...")
                conn, addr = s.accept()
                with conn:
                    print(f"[Bob] Conectado por {addr}")
                    conn.sendall(b_bytes)
                    
                    info_a = conn.recv(64)
                    if not info_a: continue
                    
                    ik_a = x25519.X25519PublicKey.from_public_bytes(info_a[:32])
                    ek_a = x25519.X25519PublicKey.from_public_bytes(info_a[32:])
                    sk_bob = bob.receber_sessao_x3dh({'ik_publica_iniciador': ik_a, 'ek_publica_iniciador': ek_a})
                    
                    sessao = SessaoSegura(sk_bob, iniciador=False)
                    
                    # Loop de chat
                    while True:
                        try:
                            dados = conn.recv(4096)
                            if not dados: 
                                print("[Bob] Alice encerrou a conexão.")
                                break
                            
                            msg = sessao.decifrar(dados)
                            if msg:
                                print(f"\n[Bob] Alice disse: '{msg}'")
                                resp = "Recebido 5/5, Alice!"
                                conn.sendall(sessao.cifrar(resp))
                                print("[Bob] Resposta enviada.")
                            else:
                                print("[Bob] Erro ao decifrar (HMAC/Formato inválido).")
                                break
                        except (ConnectionResetError, OSError):
                            print("[Bob] Conexão interrompida pelo cliente.")
                            break
                            
        except Exception as e:
            print(f"Erro no servidor: {e}")