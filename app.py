# Direitos autorais @PladixOficial

from flask import Flask, request, jsonify
import asyncio
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad
from google.protobuf.json_format import MessageToJson
import binascii
import aiohttp
import requests
import json
import like_pb2
import like_count_pb2
import uid_generator_pb2
from google.protobuf.message import DecodeError

app = Flask(__name__)

def carregar_tokens(nome_servidor):
    try:
        if nome_servidor == "IND":
            with open("token_ind.json", "r") as f:
                tokens = json.load(f)
        elif nome_servidor in {"BR", "US", "SAC", "NA", "Sg"}:
            with open("token_br.json", "r") as f:
                tokens = json.load(f)
        else:
            with open("token_bd.json", "r") as f:
                tokens = json.load(f)
        return tokens
    except Exception as e:
        app.logger.error(f"Erro ao carregar tokens para o servidor {nome_servidor}: {e}")
        return None

def criptografar_mensagem(texto_plano):
    try:
        chave = b'Yg&tc%DEuh6%Zc^8'
        iv = b'6oyZDr22E3ychjM%'
        cifra = AES.new(chave, AES.MODE_CBC, iv)
        mensagem_preenchida = pad(texto_plano, AES.block_size)
        mensagem_criptografada = cifra.encrypt(mensagem_preenchida)
        return binascii.hexlify(mensagem_criptografada).decode('utf-8')
    except Exception as e:
        app.logger.error(f"Erro ao criptografar mensagem: {e}")
        return None

def criar_mensagem_protobuf(id_usuario, regiao):
    try:
        mensagem = like_pb2.like()
        mensagem.uid = int(id_usuario)
        mensagem.region = regiao
        return mensagem.SerializeToString()
    except Exception as e:
        app.logger.error(f"Erro ao criar mensagem protobuf: {e}")
        return None

async def enviar_requisicao(uid_criptografado, token, url):
    try:
        edata = bytes.fromhex(uid_criptografado)
        cabecalhos = {
            'User-Agent': "Dalvik/2.1.0 (Linux; U; Android 9; ASUS_Z01QD Build/PI)",
            'Connection': "Keep-Alive",
            'Accept-Encoding': "gzip",
            'Authorization': f"Bearer {token}",
            'Content-Type': "application/x-www-form-urlencoded",
            'Expect': "100-continue",
            'X-Unity-Version':_collect "2018.4.11f1",
            'X-GA': "v1 1",
            'ReleaseVersion': "OB48"
        }
        async with aiohttp.ClientSession() as sessao:
            async with sessao.post(url, data=edata, headers=cabecalhos) as resposta:
                if resposta.status != 200:
                    app.logger.error(f"Falha na requisição com código de status: {resposta.status}")
                    return resposta.status
                return await resposta.text()
    except Exception as e:
        app.logger.error(f"Exceção em enviar_requisicao: {e}")
        return None

async def enviar_multiplas_requisicoes(uid, nome_servidor, url):
    try:
        regiao = nome_servidor
        mensagem_protobuf = criar_mensagem_protobuf(uid, regiao)
        if mensagem_protobuf is None:
            app.logger.error("Falha ao criar mensagem protobuf.")
            return None
        uid_criptografado = criptografar_mensagem(mensagem_protobuf)
        if uid_criptografado is None:
            app.logger.error("Falha na criptografia.")
            return None
        tarefas = []
        tokens = carregar_tokens(nome_servidor)
        if tokens is None:
            app.logger.error("Falha ao carregar tokens.")
            return None
        for i in range(100):
            token = tokens[i % len(tokens)]["token"]
            tarefas.append(enviar_requisicao(uid_criptografado, token, url))
        resultados = await asyncio.gather(*tarefas, return_exceptions=True)
        return resultados
    except Exception as e:
        app.logger.error(f"Exceção em enviar_multiplas_requisicoes: {e}")
        return None

def criar_protobuf(uid):
    try:
        mensagem = uid_generator_pb2.uid_generator()
        mensagem.saturn_ = int(uid)
        mensagem.garena = 1
        return mensagem.SerializeToString()
    except Exception as e:
        app.logger.error(f"Erro ao criar protobuf de uid: {e}")
        return None

def enc(uid):
    dados_protobuf = criar_protobuf(uid)
    if dados_protobuf is None:
        return None
    uid_criptografado = criptografar_mensagem(dados_protobuf)
    return uid_criptografado

def fazer_requisicao(criptografia, nome_servidor, token):
    try:
        if nome_servidor == "IND":
            url = "https://client.ind.freefiremobile.com/GetPlayerPersonalShow"
        elif nome_servidor in {"BR", "US", "SAC", "NA", "Sg"}:
            url = "https://client.us.freefiremobile.com/GetPlayerPersonalShow"
        else:
            url = "https://clientbp.ggblueshark.com/GetPlayerPersonalShow"
        edata = bytes.fromhex(criptografia)
        cabecalhos = {
            'User-Agent': "Dalvik/2.1.0 (Linux; U; Android 9; ASUS_Z01QD Build/PI)",
            'Connection': "Keep-Alive",
            'Accept-Encoding': "gzip",
            'Authorization': f"Bearer {token}",
            'Content-Type': "application/x-www-form-urlencoded",
            'Expect': "100-continue",
            'X-Unity-Version': "2018.4.11f1",
            'X-GA': "v1 1",
            'ReleaseVersion': "OB48"
        }
        resposta = requests.post(url, data=edata, headers=cabecalhos, verify=False)
        dados_hex = resposta.content.hex()
        binario = bytes.fromhex(dados_hex)
        decodificado = decodificar_protobuf(binario)
        if decodificado is None:
            app.logger.error("A decodificação do Protobuf retornou None.")
        return decodificado
    except Exception as e:
        app.logger.error(f"Erro em fazer_requisicao: {e}")
        return None

def decodificar_protobuf(binario):
    try:
        itens = like_count_pb2.Info()
        itens.ParseFromString(binario)
        return itens
    except DecodeError as e:
        app.logger.error(f"Erro ao decodificar dados Protobuf: {e}")
        return None
    except Exception as e:
        app.logger.error(f"Erro inesperado durante a decodificação do protobuf: {e}")
        return None

@app.route('/like', methods=['GET'])
def gerenciar_requisicoes():
    uid = request.args.get("uid")
    nome_servidor = request.args.get("server_name", "").upper()
    if not uid or not nome_servidor:
        return jsonify({"erro": "UID e nome_servidor são obrigatórios"}), 400

    try:
        def processar_requisicao():
            tokens = carregar_tokens(nome_servidor)
            if tokens is None:
                raise Exception("Falha ao carregar tokens.")
            token = tokens[0]['token']
            uid_criptografado = enc(uid)
            if uid_criptografado is None:
                raise Exception("Falha na criptografia do UID.")

            antes = fazer_requisicao(uid_criptografado, nome_servidor, token)
            if antes is None:
                raise Exception("Falha ao recuperar informações iniciais do jogador.")
            try:
                json_antes = MessageToJson(antes)
            except Exception as e:
                raise Exception(f"Erro ao converter 'antes' protobuf para JSON: {e}")
            dados_antes = json.loads(json_antes)
            curtidas_antes = dados_antes.get('AccountInfo', {}).get('Likes', 0)
            try:
                curtidas_antes = int(curtidas_antes)
            except Exception:
                curtidas_antes = 0
            app.logger.info(f"Curtidas antes do comando: {curtidas_antes}")

            if nome_servidor == "IND":
                url = "https://client.ind.freefiremobile.com/LikeProfile"
            elif nome_servidor in {"BR", "US", "SAC", "NA"}:
                url = "https://client.us.freefiremobile.com/LikeProfile"
            else:
                url = "https://clientbp.ggblueshark.com/LikeProfile"

            asyncio.run(enviar_multiplas_requisicoes(uid, nome_servidor, url))

            depois = fazer_requisicao(uid_criptografado, nome_servidor, token)
            if depois is None:
                raise Exception("Falha ao recuperar informações do jogador após requisições de curtida.")
            try:
                json_depois = MessageToJson(depois)
            except Exception as e:
                raise Exception(f"Erro ao converter 'depois' protobuf para JSON: {e}")
            dados_depois = json.loads(json_depois)
            curtidas_depois = int(dados_depois.get('AccountInfo', {}).get('Likes', 0))
            uid_jogador = int(dados_depois.get('AccountInfo', {}).get('UID', 0))
            nome_jogador = str(dados_depois.get('AccountInfo', {}).get('PlayerNickname', ''))
            curtidas_dadas = curtidas_depois - curtidas_antes
            status = 1 if curtidas_dadas != 0 else 2
            resultado = {
                "CurtidasDadasPelaAPI": curtidas_dadas,
                "CurtidasAposComando": curtidas_depois,
                "CurtidasAntesComando": curtidas_antes,
                "NomeJogador": nome_jogador,
                "UID": uid_jogador,
                "status": status
            }
            return resultado

        resultado = processar_requisicao()
        return jsonify(resultado)
    except Exception as e:
        app.logger.error(f"Erro ao processar requisição: {e}")
        return jsonify({"erro": str(e)}), 500

if __name__ == '__main__':
    app.run(debug=True, use_reloader=False)

# Direitos autorais @PladixOficial