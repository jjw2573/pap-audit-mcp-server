"""
공공감사포털(pap.go.kr) - 자체감사결과(감사보고서) 조회 MCP 서버
원격 MCP 서버 (웹 claude.ai에서 커스텀 커넥터로 등록해서 사용)

이 API는 별도 인증키(serviceKey)가 필요 없는 공개 API로 확인됨.
robots.txt 없음 / 공공누리 저작권 정책 확인됨 (KOGL 1유형: 출처표시 시 자유이용)
사용 시 반드시 출처(공공감사포털, https://pap.go.kr)를 표기할 것.

실행 전 준비:
    pip install "mcp[cli]" httpx
    python server.py
"""

import base64
import httpx
from mcp.server.fastmcp import FastMCP
from mcp.server.transport_security import TransportSecuritySettings

BASE_URL = "https://pap.go.kr/api/fdadPlanRslt"
DOWNLOAD_URL = "https://pap.go.kr/api/files/download"

# base64 인코딩 시 원본보다 커지므로, 너무 큰 파일은 컨텍스트를 과도하게 잡아먹지 않도록 제한
MAX_DOWNLOAD_BYTES = 8 * 1024 * 1024  # 8MB

# ── DNS Rebinding 방지 설정 ──────────────────────────────────
# 기본값은 localhost만 허용하므로, 실제 배포 도메인을 반드시 추가해야 함.
# Render 등 배포 후 실제 도메인으로 바꿔주세요.
security_settings = TransportSecuritySettings(
    enable_dns_rebinding_protection=True,
    allowed_hosts=[
        "localhost",
        "127.0.0.1",
        "pap-audit-mcp-server.onrender.com",
    ],
    allowed_origins=[
        "https://claude.ai",
        "https://*.claude.ai",
    ],
)

mcp = FastMCP("공공감사포털-자체감사결과조회", stateless_http=True, transport_security=security_settings)

# 서버에 과도한 부담을 주지 않기 위한 안전장치
DEFAULT_TIMEOUT = 15.0
REQUEST_HEADERS = {
    "User-Agent": "MCP-AuditReportClient/1.0 (audit report lookup tool)"
}


@mcp.tool()
async def search_audit_results(
    inst_nm: str = "",
    search_ymd_bgng: str = "",
    search_ymd_end: str = "",
    palaw_inst_clsf_cd: str = "",
    size: int = 10,
    page: int = 0,
) -> str:
    """
    공공감사포털(pap.go.kr)에서 자체감사결과(감사보고서)를 검색합니다.
    감사원 산하 각 공공기관의 자체감사 결과(복무감사, 특정감사 등)를 조회할 수 있어요.

    Args:
        inst_nm: 기관명 (예: "한국산업단지공단"). 비워두면 전체 기관 대상 검색.
        search_ymd_bgng: 검색 시작일 (YYYYMMDD 형식, 예: "20250727"). 비워두면 기본 범위 적용.
        search_ymd_end: 검색 종료일 (YYYYMMDD 형식, 예: "20260727").
        palaw_inst_clsf_cd: 기관분류 코드. 비워두면 전체.
        size: 한 페이지 결과 수 (기본 10)
        page: 페이지 번호, 0부터 시작 (기본 0)

    Returns:
        검색된 감사결과 목록을 사람이 읽기 쉬운 텍스트로 정리한 결과.
        (원 출처: 공공감사포털 https://pap.go.kr, 공공누리 1유형)
    """
    params = {
        "searchYmdBgng": search_ymd_bgng,
        "searchYmdEnd": search_ymd_end,
        # API가 두 가지 날짜 포맷(YYYYMMDD / YYYY-MM-DD)을 동시에 요구하는 것으로 관찰됨
        "searchYmdBgngA": _to_dashed(search_ymd_bgng),
        "searchYmdEndA": _to_dashed(search_ymd_end),
        "instNm": inst_nm,
        "palawInstClsfCd": palaw_inst_clsf_cd,
        "size": size,
        "index": 0,
        "page": page,
    }

    async with httpx.AsyncClient(timeout=DEFAULT_TIMEOUT, headers=REQUEST_HEADERS) as client:
        resp = await client.get(BASE_URL, params=params)
        resp.raise_for_status()
        data = resp.json()

    return _format_results(data)


@mcp.tool()
async def download_audit_report_file(file_id: str, file_sn: int = 1) -> str:
    """
    공공감사포털(pap.go.kr)에서 감사보고서 첨부파일(원문)을 다운로드합니다.
    search_audit_results 결과의 subList 안에 있는 'rlsDocAtchFileUuid' 값을 file_id로 사용하세요.

    Args:
        file_id: 첨부파일 UUID (search_audit_results 결과의 rlsDocAtchFileUuid)
        file_sn: 파일 일련번호. 첨부파일이 여러 개일 경우 순서(기본 1)

    Returns:
        파일명, 형식, 크기 정보와 base64로 인코딩된 파일 내용(JSON 문자열).
        파일이 너무 크면 내용 대신 안내 메시지를 반환합니다.
        (출처: 공공감사포털 https://pap.go.kr, 공공누리 1유형 - 재사용 시 출처표시 필요)
    """
    payload = {"fileId": file_id, "fileSn": file_sn}

    async with httpx.AsyncClient(timeout=DEFAULT_TIMEOUT, headers=REQUEST_HEADERS) as client:
        resp = await client.post(DOWNLOAD_URL, json=payload)
        resp.raise_for_status()
        content = resp.content

        content_type = resp.headers.get("content-type", "application/octet-stream")
        disposition = resp.headers.get("content-disposition", "")
        filename = _parse_filename(disposition) or f"{file_id}_{file_sn}"

    if len(content) > MAX_DOWNLOAD_BYTES:
        return (
            f'{{"filename": "{filename}", "content_type": "{content_type}", '
            f'"size_bytes": {len(content)}, '
            f'"error": "파일이 너무 커서 base64로 전달하지 않았습니다 (제한: {MAX_DOWNLOAD_BYTES} bytes)."}}'
        )

    encoded = base64.b64encode(content).decode("ascii")
    return (
        f'{{"filename": "{filename}", "content_type": "{content_type}", '
        f'"size_bytes": {len(content)}, "base64_content": "{encoded}", '
        f'"source": "공공감사포털 https://pap.go.kr (공공누리 1유형)"}}'
    )


def _parse_filename(content_disposition: str) -> str:
    """Content-Disposition 헤더에서 파일명 추출."""
    if not content_disposition:
        return ""
    # filename*=UTF-8''xxx.pdf 형태 우선 처리
    for part in content_disposition.split(";"):
        part = part.strip()
        if part.lower().startswith("filename*="):
            value = part.split("=", 1)[1]
            if "''" in value:
                value = value.split("''", 1)[1]
            from urllib.parse import unquote
            return unquote(value.strip('"'))
        if part.lower().startswith("filename="):
            return part.split("=", 1)[1].strip('"')
    return ""


def _to_dashed(ymd: str) -> str:
    """YYYYMMDD -> YYYY-MM-DD 변환. 빈 값이면 그대로 반환."""
    if len(ymd) == 8 and ymd.isdigit():
        return f"{ymd[0:4]}-{ymd[4:6]}-{ymd[6:8]}"
    return ymd


def _format_results(data: dict) -> str:
    embedded = data.get("_embedded", {})
    items = embedded.get("fdadPlanRsltListDtoes", [])
    total = data.get("page", {}).get("totalElements", len(items))

    if not items:
        return "검색 결과가 없습니다."

    lines = [f"총 {total}건 중 {len(items)}건 표시\n(출처: 공공감사포털 https://pap.go.kr)\n"]

    for i, item in enumerate(items, 1):
        lines.append(f"[{i}] {item.get('instCdNm', '-')} | {item.get('adFldNm', '-')} ({item.get('adYr', '-')}년)")
        lines.append(f"    사안: {item.get('adMttrNm', '-')}")
        lines.append(f"    감사기간: {item.get('adBgngYmd', '-')} ~ {item.get('adEndYmd', '-')}")
        lines.append(f"    중점사항: {item.get('adEmphsMttr', '-')}")

        for sub in item.get("subList", []) or []:
            lines.append(
                f"      - 지적사항: {sub.get('indicMttrTtl', '-')} "
                f"/ 관련기관: {sub.get('instNm', '-')} "
                f"/ 처분: {sub.get('dsprqKindList', '-')}"
            )
            file_uuid = sub.get("rlsDocAtchFileUuid")
            if file_uuid:
                lines.append(f"        └ 첨부파일ID: {file_uuid}")
        lines.append("")

    return "\n".join(lines)


app = mcp.streamable_http_app()

if __name__ == "__main__":
    mcp.run(transport="streamable-http")
