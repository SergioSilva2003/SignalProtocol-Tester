import os
from cryptography.hazmat.primitives.asymmetric import x25519
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

# --- SIMULAÇÃO KEM (O "Cofre" Pós-Quântico) ---
class SimulacaoKyber:
    @staticmethod
    def gerar_chaves():
        priv = x25519.X25519PrivateKey.generate()
        pub = priv.public_key()
        return priv, pub

    @staticmethod
    def encapsular(pub_key_destino):
        # Alice gera segredo e tranca-o
        ephemeral_priv = x25519.X25519PrivateKey.generate()
        ciphertext = ephemeral_priv.public_key().public_bytes(
            serialization.Encoding.Raw, serialization.PublicFormat.Raw
        )
        shared_secret = ephemeral_priv.exchange(pub_key_destino)
        return ciphertext, shared_secret

    @staticmethod
    def desencapsular(ciphertext_bytes, priv_key_dono):
        # Bob destranca o cofre
        peer_public_key = x25519.X25519PublicKey.from_public_bytes(ciphertext_bytes)
        shared_secret = priv_key_dono.exchange(peer_public_key)
        return shared_secret

# --- FUNÇÕES AUXILIARES ---
def generate_x25519_keys():
    private_key = x25519.X25519PrivateKey.generate()
    public_key = private_key.public_key()
    return private_key, public_key

def derive_key(input_material, info):
    hkdf = HKDF(
        algorithm=hashes.SHA256(), length=32, salt=None, info=info, backend=default_backend()
    )
    return hkdf.derive(input_material)

# --- CLASSE PARTICIPANTE ---
class Participante:
    def __init__(self, nome):
        self.nome = nome
        print(f"[{self.nome}] A gerar chaves (incluindo Pós-Quântica)...")
        self.ik_private, self.ik_public = generate_x25519_keys()
        self.spk_private, self.spk_public = generate_x25519_keys()
        self.opk_private, self.opk_public = generate_x25519_keys()
        # Chave PQ
        self.pq_private, self.pq_public = SimulacaoKyber.gerar_chaves()

    def gerar_bundle_publico(self):
        return {
            'ik_publica': self.ik_public,
            'spk_publica': self.spk_public,
            'opk_publica': self.opk_public,
            'pq_publica': self.pq_public
        }

    def iniciar_sessao_x3dh(self, bundle_recetor):
        print(f"[{self.nome}] A iniciar sessão Híbrida (X3DH + PQ)...")
        ek_private, ek_public = generate_x25519_keys()
        
        dh1 = self.ik_private.exchange(bundle_recetor['spk_publica'])
        dh2 = ek_private.exchange(bundle_recetor['ik_publica'])
        dh3 = ek_private.exchange(bundle_recetor['spk_publica'])
        dh4 = ek_private.exchange(bundle_recetor['opk_publica'])
        
        # KEM Encapsulate
        pq_ciphertext, pq_shared_secret = SimulacaoKyber.encapsular(bundle_recetor['pq_publica'])
        
        ikm = dh1 + dh2 + dh3 + dh4 + pq_shared_secret
        sk = derive_key(ikm, info=b'x3dh-pq-shared-secret')
        print(f"[{self.nome}] SK Final: {sk.hex().upper()}")

        info_para_recetor = {
            'ik_publica_iniciador': self.ik_public,
            'ek_publica_iniciador': ek_public,
            'pq_ciphertext': pq_ciphertext
        }
        return sk, info_para_recetor

    def receber_sessao_x3dh(self, info_iniciador):
        print(f"[{self.nome}] A receber sessão Híbrida...")
        ik_alice = info_iniciador['ik_publica_iniciador']
        ek_alice = info_iniciador['ek_publica_iniciador']
        ciphertext = info_iniciador['pq_ciphertext']
        
        dh1 = self.spk_private.exchange(ik_alice)
        dh2 = self.ik_private.exchange(ek_alice)
        dh3 = self.spk_private.exchange(ek_alice)
        dh4 = self.opk_private.exchange(ek_alice)
        
        # KEM Decapsulate
        pq_shared_secret = SimulacaoKyber.desencapsular(ciphertext, self.pq_private)
        
        ikm = dh1 + dh2 + dh3 + dh4 + pq_shared_secret
        sk = derive_key(ikm, info=b'x3dh-pq-shared-secret')
        print(f"[{self.nome}] SK Final: {sk.hex().upper()}")
        return sk

# --- CLASSE SESSÃO SEGURA ---
class SessaoSegura:
    def __init__(self, sk_inicial, iniciador=False):
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

    def derivar(self, chave, info):
        hkdf = HKDF(algorithm=hashes.SHA256(), length=32, salt=None, info=info, backend=default_backend())
        return hkdf.derive(chave)

    def _avancar_catraca_simetrica(self, chain_key):
        msg_key = self.derivar(chain_key, b"chave-mensagem")
        next_chain = self.derivar(chain_key, b"proxima-chain-key")
        return msg_key, next_chain

    def _avancar_catraca_assimetrica(self, other_pub, chain_type):
        dh_secret = self.dh_ratchet_private.exchange(other_pub)
        root_input = self.root_key + dh_secret
        self.root_key = self.derivar(root_input, b"nova-root-key")
        nova_chain = self.derivar(self.root_key, b"nova-chain-key")
        if chain_type == "send": self.chain_key_send = nova_chain
        elif chain_type == "recv":
            self.chain_key_recv = nova_chain
            self.dh_ratchet_private, self.dh_ratchet_public = generate_x25519_keys()

    def cifrar(self, plaintext):
        if self.other_party_dh_public:
            self._avancar_catraca_assimetrica(self.other_party_dh_public, "send")
            self.other_party_dh_public = None 
        msg_key, next_chain = self._avancar_catraca_simetrica(self.chain_key_send)
        self.chain_key_send = next_chain
        aesgcm = AESGCM(msg_key)
        nonce = os.urandom(12)
        ciphertext = aesgcm.encrypt(nonce, plaintext.encode('utf-8'), None)
        pub_bytes = self.dh_ratchet_public.public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
        return pub_bytes + nonce + ciphertext

    def decifrar(self, data):
        try:
            pub_bytes = data[:32]; nonce = data[32:44]; ciphertext = data[44:]
            incoming_pub = x25519.X25519PublicKey.from_public_bytes(pub_bytes)
        except: return None
        
        if not self.sou_iniciador and not self.sessao_inicializada: #se por acaso o outro nao alterou a catraca assimetrica entao eu decifro o que o outro enviou e rodo a catraca assimetrica para poder responder-lo
        
            self.other_party_dh_public = incoming_pub 
            try:
                msg_key, next_chain = self._avancar_catraca_simetrica(self.chain_key_recv)
                plaintext = AESGCM(msg_key).decrypt(nonce, ciphertext, None).decode('utf-8')
                self.chain_key_recv = next_chain
                self.dh_ratchet_private, self.dh_ratchet_public = generate_x25519_keys()
                dh_secret = self.dh_ratchet_private.exchange(incoming_pub)
                root_input = self.root_key + dh_secret
                self.root_key = self.derivar(root_input, b"nova-root-key")
                self.chain_key_send = self.derivar(self.root_key, b"nova-chain-key")
                self.sessao_inicializada = True; self.other_party_dh_public = None 
                return plaintext
            except: return None

        if self.other_party_dh_public != incoming_pub: #se a chave do outro mudar enquanto esta a enviar mensagens para eu decifrar eu rodo a minha catraca assimetrica para estar sincronizado com a chave publica do outro
            self._avancar_catraca_assimetrica(incoming_pub, "recv")
            self.other_party_dh_public = incoming_pub
        
        try:
            msg_key, next_chain = self._avancar_catraca_simetrica(self.chain_key_recv) #procede a decrifrar com a catraca simetrica pois o outro ainda esta a enviar mensagens
            plaintext = AESGCM(msg_key).decrypt(nonce, ciphertext, None).decode('utf-8')
            self.chain_key_recv = next_chain
            return plaintext
        except: return None