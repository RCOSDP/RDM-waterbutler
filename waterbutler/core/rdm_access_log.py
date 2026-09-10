"""GakuNin RDM アクセスログ 操作者識別フィールド (WaterButler 側)

ファイルのアップロード・ダウンロードの実体は WaterButler を経由するため、
RDM-osf.io 側だけを改修しても「誰がどのファイルを取得したか」は不明の
まま残る。

WaterButler は認可のため OSF の ``/api/v1/files/auth/`` を呼び、その
レスポンス (JWE+JWT) を ``ProviderHandler.self.auth`` に保持している。
RDM-osf.io の ``addons/base/views.py:get_auth()`` がこのレスポンスに
``rdm_log`` キーを同梱するので、ここではそれを取り出して同一形式で
出力するだけでよい。

  - 認証判定・PAT/OAuth2 の判別・Cookie のハッシュ化はすべて OSF 側で
    完結しており、WB 側では一切行わない (JWE_SECRET/JWT_SECRET 以外の
    秘密情報を WB に持たせない)。
  - OSF 側が古い場合 ``rdm_log`` は存在しない。その場合は
    ``payload['auth']['id']`` (make_auth() の GUID) にフォールバックする。

出力形式は RDM-osf.io 側と同一:
    {"auth": "...", "user": "...", "cred": "..."}
"""

import json
import logging
import logging.handlers
import os
import sys

AUTH_WB_UNKNOWN = 'wb:unknown'

_LOG_PREFIX = 'RDM_ACCESS_LOG '

logger = logging.getLogger('rdm.accesslog')


def _init_logger():
    if getattr(logger, '_rdm_configured', False):
        return logger
    path = os.environ.get('RDM_ACCESS_LOG_PATH')
    if path:
        handler = logging.handlers.WatchedFileHandler(path)
    else:
        handler = logging.StreamHandler(sys.stdout)
    handler.setFormatter(logging.Formatter('%(message)s'))
    logger.handlers = [handler]
    logger.setLevel(logging.INFO)
    logger.propagate = False
    logger._rdm_configured = True
    return logger


def fields_from_payload(payload):
    """OSF の認可レスポンスから (auth, user, cred) を取り出す。"""
    if not payload:
        return AUTH_WB_UNKNOWN, None, None

    rdm_log = payload.get('rdm_log')
    if isinstance(rdm_log, dict):
        return (rdm_log.get('auth') or AUTH_WB_UNKNOWN,
                rdm_log.get('user'),
                rdm_log.get('cred'))

    # OSF 側が未改修の場合のフォールバック。
    # make_auth() は認証済みなら {'id': <GUID>, ...}、未認証なら {} を返す。
    guid = (payload.get('auth') or {}).get('id')
    return AUTH_WB_UNKNOWN, guid, None


def emit_from_payload(payload):
    """アクセスログ 1 行を JSON Lines で出力する。

    この関数は例外を投げない。ログ出力の失敗がリクエスト処理を
    妨げてはならない。
    """
    try:
        auth, user, cred = fields_from_payload(payload)
        rec = {'auth': auth}
        if user:
            rec['user'] = user
        if cred:
            rec['cred'] = cred
        _init_logger().info(
            _LOG_PREFIX + json.dumps(rec, ensure_ascii=False, sort_keys=True))
    except Exception:
        try:
            logging.getLogger(__name__).exception('rdm_access_log: emit failed')
        except Exception:
            pass
