from __future__ import annotations

from app.models.report import RiskStatus


RECOMMENDED_ACTIONS: dict[RiskStatus, list[str]] = {
    "SAFE": [
        "Manter monitoramento regular",
        "Revisar periodicamente chaves SSH autorizadas",
        "Verificar atualizações de segurança pendentes",
    ],
    "SUSPICIOUS": [
        "Investigar processos e portas suspeitas identificadas",
        "Revisar e auditar chaves SSH",
        "Verificar logs de autenticação (/var/log/auth.log)",
        "Monitorar a máquina de perto nas próximas 24h",
    ],
    "COMPROMISED": [
        "Isolar a máquina da rede imediatamente",
        "Revisar e remover chaves SSH desconhecidas",
        "Encerrar processos suspeitos",
        "Analisar logs de autenticação e acesso",
        "Considerar rebuild completo da máquina",
        "Notificar equipe de segurança / CSIRT",
    ],
}


def get_recommended_actions(status: RiskStatus) -> list[str]:
    return RECOMMENDED_ACTIONS.get(status, [])
