# (Importações e Classes Participante/SessaoSegura mantêm-se iguais)
# Apenas a parte final (bloco __main__) foi alterada para aguardar a resposta.

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
    """Gera um par de chaves X25519 (privada, publica)."""
    private_key = x25519.X25519PrivateKey.generate()
    public_key = private_key.public_key()
    return private_key, public_key

def derive_key(input_material, info):
    """Deriva uma chave final de 32 bytes usando HKDF."""
    hkdf = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=None,
        info=info,
        backend=default_backend()
    )
    return hkdf.derive(input_material)

# --- 3. Definição da Classe Participante (X3DH) ---

class Participante:
    def __init__(self, nome):
        self.nome = nome
        print(f"[{self.nome}] A gerar chaves...")
        self.ik_private, self.ik_public = generate_x25519_keys()
        self.spk_private, self.spk_public = generate_x25519_keys()
        self.opk_private, self.opk_public = generate_x25519_keys()

    def gerar_bundle_publico(self):
        print(f"[{self.nome}] A publicar o 'bundle' de chaves públicas.")
        return {
            'ik_publica': self.ik_public,
            'spk_publica': self.spk_public,
            'opk_publica': self.opk_public
        }

    def iniciar_sessao_x3dh(self, bundle_recetor):
        print(f"[{self.nome}] A iniciar sessão X3DH...")
        ek_private, ek_public = generate_x25519_keys()
        
        ik_recetor = bundle_recetor['ik_publica']
        spk_recetor = bundle_recetor['spk_publica']
        opk_recetor = bundle_recetor['opk_publica']

        dh1 = self.ik_private.exchange(spk_recetor)
        dh2 = ek_private.exchange(ik_recetor)
        dh3 = ek_private.exchange(spk_recetor)
        dh4 = ek_private.exchange(opk_recetor)
        
        ikm = dh1 + dh2 + dh3 + dh4
        sk = derive_key(ikm, info=b'x3dh-shared-secret')
        print(f"[{self.nome}] SK calculado: {sk.hex()}")

        info_para_recetor = {
            'ik_publica_iniciador': self.ik_public,
            'ek_publica_iniciador': ek_public
        }
        return sk, info_para_recetor

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

# --- 4. Definição da Classe SessaoSegura (CORRIGIDA) ---

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
        elif chain_para_atualizar == "recv":
            self.chain_key_recv = nova_chain_key
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

# --- 5. Bloco de Execução Principal (Alice) ---

if __name__ == "__main__":
    HOST = '127.0.0.1'
    PORT = 9999
    
    print("--- ALICE (Cliente) ---")
    alice = Participante("Alice")

    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.connect((HOST, PORT))
            print(f"Conectado a {HOST}:{PORT}")
            
            # FASE 1: X3DH
            print("\n## FASE 1: X3DH ##")
            bundle_bytes = s.recv(96)
            ik_bob = x25519.X25519PublicKey.from_public_bytes(bundle_bytes[:32])
            spk_bob = x25519.X25519PublicKey.from_public_bytes(bundle_bytes[32:64])
            opk_bob = x25519.X25519PublicKey.from_public_bytes(bundle_bytes[64:])
            
            bundle_bob = {'ik_publica': ik_bob, 'spk_publica': spk_bob, 'opk_publica': opk_bob}
            sk_alice, info_bob = alice.iniciar_sessao_x3dh(bundle_bob)
            
            ik_a = info_bob['ik_publica_iniciador'].public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
            ek_a = info_bob['ek_publica_iniciador'].public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
            s.sendall(ik_a + ek_a)
            
            # FASE 2: Double Ratchet
            print("\n## FASE 2: Double Ratchet ##")
            sessao = SessaoSegura(sk_alice, iniciador=True)

            # --- MENSAGEM 1 ---
            msg1 = "Olá Bob! Isto é um teste."
            s.sendall(sessao.cifrar(msg1))
            print("[Alice] Msg 1 enviada.")

            resp1 = s.recv(4096)
            print(f"\n[Alice] Resposta 1 decifrada: '{sessao.decifrar(resp1)}'")
            
            # --- MENSAGEM 2 ---
            msg2 = "Funcionou! Sincronização perfeita."
            s.sendall(sessao.cifrar(msg2))
            print("[Alice] Msg 2 enviada.")

            # --- CORREÇÃO: Aguardar a resposta da Msg 2 antes de fechar ---
            resp2 = s.recv(4096)
            if resp2:
                print(f"\n[Alice] Resposta 2 decifrada: '{sessao.decifrar(resp2)}'")
            
            print("\n[Alice] Chat terminado com sucesso.")
            
    except ConnectionRefusedError:
        print("Erro: Inicie o bob.py primeiro.")
    except Exception as e:
        print(f"Erro na Alice: {e}")