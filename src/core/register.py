"""
注册流程引擎
从 main.py 中提取并重构的注册流程
"""

import re
import json
import time
import logging
import secrets
import string
import urllib.parse
from typing import Optional, Dict, Any, Tuple, Callable
from dataclasses import dataclass
from datetime import datetime

from curl_cffi import requests as cffi_requests

from .openai.oauth import OAuthManager, OAuthStart
from .http_client import OpenAIHTTPClient, HTTPClientError
from ..services import EmailServiceFactory, BaseEmailService, EmailServiceType
from ..database import crud
from ..database.session import get_db
from ..config.constants import (
    OPENAI_API_ENDPOINTS,
    OPENAI_PAGE_TYPES,
    generate_random_user_info,
    OTP_CODE_PATTERN,
    DEFAULT_PASSWORD_LENGTH,
    PASSWORD_CHARSET,
    AccountStatus,
    TaskStatus,
)
from ..config.settings import get_settings


logger = logging.getLogger(__name__)


@dataclass
class RegistrationResult:
    """注册结果"""
    success: bool
    email: str = ""
    password: str = ""  # 注册密码
    account_id: str = ""
    workspace_id: str = ""
    access_token: str = ""
    refresh_token: str = ""
    id_token: str = ""
    session_token: str = ""  # 会话令牌
    error_message: str = ""
    logs: list = None
    metadata: dict = None
    source: str = "register"  # 'register' 或 'login'，区分账号来源

    def to_dict(self) -> Dict[str, Any]:
        """转换为字典"""
        return {
            "success": self.success,
            "email": self.email,
            "password": self.password,
            "account_id": self.account_id,
            "workspace_id": self.workspace_id,
            "access_token": self.access_token[:20] + "..." if self.access_token else "",
            "refresh_token": self.refresh_token[:20] + "..." if self.refresh_token else "",
            "id_token": self.id_token[:20] + "..." if self.id_token else "",
            "session_token": self.session_token[:20] + "..." if self.session_token else "",
            "error_message": self.error_message,
            "logs": self.logs or [],
            "metadata": self.metadata or {},
            "source": self.source,
        }


@dataclass
class SignupFormResult:
    """提交注册表单的结果"""
    success: bool
    page_type: str = ""  # 响应中的 page.type 字段
    is_existing_account: bool = False  # 是否为已注册账号
    response_data: Dict[str, Any] = None  # 完整的响应数据
    error_message: str = ""


class RegistrationEngine:
    """
    注册引擎
    负责协调邮箱服务、OAuth 流程和 OpenAI API 调用
    """

    def __init__(
        self,
        email_service: BaseEmailService,
        proxy_url: Optional[str] = None,
        callback_logger: Optional[Callable[[str], None]] = None,
        task_uuid: Optional[str] = None
    ):
        """
        初始化注册引擎

        Args:
            email_service: 邮箱服务实例
            proxy_url: 代理 URL
            callback_logger: 日志回调函数
            task_uuid: 任务 UUID（用于数据库记录）
        """
        self.email_service = email_service
        self.proxy_url = proxy_url
        self.callback_logger = callback_logger or (lambda msg: logger.info(msg))
        self.task_uuid = task_uuid

        # 创建 HTTP 客户端
        self.http_client = OpenAIHTTPClient(proxy_url=proxy_url)

        # 创建 OAuth 管理器
        settings = get_settings()
        self.oauth_manager = OAuthManager(
            client_id=settings.openai_client_id,
            auth_url=settings.openai_auth_url,
            token_url=settings.openai_token_url,
            redirect_uri=settings.openai_redirect_uri,
            scope=settings.openai_scope,
            proxy_url=proxy_url  # 传递代理配置
        )

        # 状态变量
        self.email: Optional[str] = None
        self.password: Optional[str] = None  # 注册密码
        self.email_info: Optional[Dict[str, Any]] = None
        self.oauth_start: Optional[OAuthStart] = None
        self.session: Optional[cffi_requests.Session] = None
        self.session_token: Optional[str] = None  # 会话令牌
        self._device_id: Optional[str] = None  # 当前 OAuth 流程的 device id
        self._auth_referer: Optional[str] = None  # OAuth bootstrap 最终落点
        self._last_otp_validation_payload: Dict[str, Any] = {}
        self.logs: list = []
        self._otp_sent_at: Optional[float] = None  # OTP 发送时间戳
        self._is_existing_account: bool = False  # 是否为已注册账号（用于自动登录）
        self._token_acquisition_requires_login: bool = False  # 新注册账号需要二次登录拿 token

    def _log(self, message: str, level: str = "info"):
        """记录日志"""
        timestamp = datetime.now().strftime("%H:%M:%S")
        log_message = f"[{timestamp}] {message}"

        # 添加到日志列表
        self.logs.append(log_message)

        # 调用回调函数
        if self.callback_logger:
            self.callback_logger(log_message)

        # 记录到数据库（如果有关联任务）
        if self.task_uuid:
            try:
                with get_db() as db:
                    crud.append_task_log(db, self.task_uuid, log_message)
            except Exception as e:
                logger.warning(f"记录任务日志失败: {e}")

        # 根据级别记录到日志系统
        if level == "error":
            logger.error(message)
        elif level == "warning":
            logger.warning(message)
        else:
            logger.info(message)

    def _generate_password(self, length: int = DEFAULT_PASSWORD_LENGTH) -> str:
        """生成随机密码"""
        return ''.join(secrets.choice(PASSWORD_CHARSET) for _ in range(length))

    def _check_ip_location(self) -> Tuple[bool, Optional[str]]:
        """检查 IP 地理位置"""
        try:
            return self.http_client.check_ip_location()
        except Exception as e:
            self._log(f"检查 IP 地理位置失败: {e}", "error")
            return False, None

    def _create_email(self) -> bool:
        """创建邮箱"""
        try:
            self._log(f"正在创建 {self.email_service.service_type.value} 邮箱，先给新账号整个收件箱...")
            self.email_info = self.email_service.create_email()

            if not self.email_info or "email" not in self.email_info:
                self._log("创建邮箱失败: 返回信息不完整", "error")
                return False

            self.email = self.email_info["email"]
            self._log(f"邮箱已就位，地址新鲜出炉: {self.email}")
            return True

        except Exception as e:
            self._log(f"创建邮箱失败: {e}", "error")
            return False

    def _start_oauth(self) -> bool:
        """开始 OAuth 流程"""
        try:
            self._log("开始 OAuth 授权流程，去门口刷个脸...")
            self.oauth_start = self.oauth_manager.start_oauth()
            self._log(f"OAuth URL 已备好，通道已经打开: {self.oauth_start.auth_url[:80]}...")
            return True
        except Exception as e:
            self._log(f"生成 OAuth URL 失败: {e}", "error")
            return False

    def _init_session(self) -> bool:
        """初始化会话"""
        try:
            self.session = self.http_client.session
            return True
        except Exception as e:
            self._log(f"初始化会话失败: {e}", "error")
            return False

    def _get_device_id(self) -> Optional[str]:
        """获取 Device ID"""
        if not self.oauth_start:
            return None

        max_attempts = 3
        for attempt in range(1, max_attempts + 1):
            try:
                if not self.session:
                    self.session = self.http_client.session

                response = self.session.get(
                    self.oauth_start.auth_url,
                    timeout=20
                )
                final_url = str(getattr(response, "url", "") or self.oauth_start.auth_url)
                if final_url.startswith("https://auth.openai.com"):
                    self._auth_referer = final_url
                did = self.session.cookies.get("oai-did")

                if did:
                    self._device_id = did
                    self._log(f"Device ID: {did}")
                    return did

                self._log(
                    f"获取 Device ID 失败: 未返回 oai-did Cookie (HTTP {response.status_code}, 第 {attempt}/{max_attempts} 次)",
                    "warning" if attempt < max_attempts else "error"
                )
            except Exception as e:
                self._log(
                    f"获取 Device ID 失败: {e} (第 {attempt}/{max_attempts} 次)",
                    "warning" if attempt < max_attempts else "error"
                )

            if attempt < max_attempts:
                time.sleep(attempt)
                self.http_client.close()
                self.session = self.http_client.session

        return None

    def _check_sentinel(self, did: str, *, flow: str = "authorize_continue") -> Optional[str]:
        """检查 Sentinel 拦截"""
        try:
            sen_token = self.http_client.check_sentinel(did, flow=flow)
            if sen_token:
                self._log(f"Sentinel token 获取成功")
                return sen_token
            self._log("Sentinel 检查失败: 未获取到 token", "warning")
            return None

        except Exception as e:
            self._log(f"Sentinel 检查异常: {e}", "warning")
            return None

    def _submit_auth_start(
        self,
        did: str,
        sen_token: Optional[str],
        *,
        screen_hint: str,
        referer: str,
        log_label: str,
        record_existing_account: bool = True,
    ) -> SignupFormResult:
        """
        提交授权入口表单

        Returns:
            SignupFormResult: 提交结果，包含账号状态判断
        """
        try:
            current_did = did
            current_sen_token = sen_token
            current_referer = self._auth_referer or referer
            response = None
            for attempt in range(2):
                request_body = json.dumps({
                    "username": {
                        "value": self.email,
                        "kind": "email",
                    },
                    "screen_hint": screen_hint,
                })

                headers = self._build_openai_json_headers(current_referer)

                if current_sen_token:
                    headers["openai-sentinel-token"] = self.http_client.build_sentinel_header(
                        device_id=current_did,
                        flow="authorize_continue",
                        token=current_sen_token,
                    )

                response = self.session.post(
                    OPENAI_API_ENDPOINTS["signup"],
                    headers=headers,
                    data=request_body,
                )

                status_label = f"{log_label}状态" if attempt == 0 else f"{log_label}重试状态"
                self._log(f"{status_label}: {response.status_code}")

                if response.status_code == 400:
                    body_preview = (response.text or "")[:240]
                    if body_preview:
                        self._log(f"{log_label}失败响应: {body_preview}", "warning")
                    if "invalid_auth_step" in (response.text or "") and attempt == 0:
                        self._log(f"{log_label}收到 invalid_auth_step，重新热身授权会话后重试一次", "warning")
                        self._reset_auth_flow()
                        retry_did, retry_sen_token = self._prepare_authorize_flow(f"{log_label}重试")
                        if not retry_did:
                            return SignupFormResult(
                                success=False,
                                error_message="invalid_auth_step 后重试时获取 Device ID 失败"
                            )
                        if not retry_sen_token:
                            return SignupFormResult(
                                success=False,
                                error_message="invalid_auth_step 后重试时 Sentinel POW 验证失败"
                            )
                        current_did = retry_did
                        current_sen_token = retry_sen_token
                        current_referer = self._auth_referer or referer
                        continue
                break

            if response is None or response.status_code != 200:
                return SignupFormResult(
                    success=False,
                    error_message=f"HTTP {response.status_code if response is not None else 0}: {(response.text[:200] if response is not None else '')}"
                )

            # 解析响应判断账号状态
            try:
                response_data = response.json()
                page_type = response_data.get("page", {}).get("type", "")
                self._log(f"响应页面类型: {page_type}")

                is_existing = page_type == OPENAI_PAGE_TYPES["EMAIL_OTP_VERIFICATION"]

                if is_existing:
                    self._otp_sent_at = time.time()
                    if record_existing_account:
                        self._log(f"检测到已注册账号，将自动切换到登录流程")
                        self._is_existing_account = True
                    else:
                        self._log("登录流程已触发，等待系统自动发送的验证码")

                return SignupFormResult(
                    success=True,
                    page_type=page_type,
                    is_existing_account=is_existing,
                    response_data=response_data
                )

            except Exception as parse_error:
                self._log(f"解析响应失败: {parse_error}", "warning")
                # 无法解析，默认成功
                return SignupFormResult(success=True)

        except Exception as e:
            self._log(f"{log_label}失败: {e}", "error")
            return SignupFormResult(success=False, error_message=str(e))

    def _submit_signup_form(
        self,
        did: str,
        sen_token: Optional[str],
        *,
        record_existing_account: bool = True,
    ) -> SignupFormResult:
        """提交注册入口表单。"""
        return self._submit_auth_start(
            did,
            sen_token,
            screen_hint="signup",
            referer="https://auth.openai.com/create-account",
            log_label="提交注册表单",
            record_existing_account=record_existing_account,
        )

    def _submit_login_start(self, did: str, sen_token: Optional[str]) -> SignupFormResult:
        """提交登录入口表单。"""
        return self._submit_auth_start(
            did,
            sen_token,
            screen_hint="login",
            referer="https://auth.openai.com/log-in",
            log_label="提交登录入口",
            record_existing_account=False,
        )

    def _submit_login_password(self) -> SignupFormResult:
        """提交登录密码，进入邮箱验证码页面。"""
        try:
            did = self._device_id or self.session.cookies.get("oai-did")
            if not did:
                return SignupFormResult(success=False, error_message="登录密码前缺少 Device ID")
            sen_token = self._check_sentinel(did, flow="password_verify")
            if not sen_token:
                return SignupFormResult(success=False, error_message="登录密码阶段 Sentinel POW 验证失败")
            headers = self._build_openai_json_headers("https://auth.openai.com/log-in/password")
            headers["openai-sentinel-token"] = self.http_client.build_sentinel_header(
                device_id=did,
                flow="password_verify",
                token=sen_token,
            )
            response = self.session.post(
                OPENAI_API_ENDPOINTS["password_verify"],
                headers=headers,
                data=json.dumps({"password": self.password}),
            )

            self._log(f"提交登录密码状态: {response.status_code}")

            if response.status_code != 200:
                return SignupFormResult(
                    success=False,
                    error_message=f"HTTP {response.status_code}: {response.text[:200]}"
                )

            response_data = response.json()
            page_type = response_data.get("page", {}).get("type", "")
            self._log(f"登录密码响应页面类型: {page_type}")

            is_existing = page_type == OPENAI_PAGE_TYPES["EMAIL_OTP_VERIFICATION"]
            if is_existing:
                self._otp_sent_at = time.time()
                self._log("登录密码校验通过，等待系统自动发送的验证码")

            return SignupFormResult(
                success=True,
                page_type=page_type,
                is_existing_account=is_existing,
                response_data=response_data,
            )

        except Exception as e:
            self._log(f"提交登录密码失败: {e}", "error")
            return SignupFormResult(success=False, error_message=str(e))

    def _reset_auth_flow(self) -> None:
        """重置会话，准备重新发起 OAuth 流程。"""
        self.http_client.close()
        self.session = None
        self.oauth_start = None
        self.session_token = None
        self._otp_sent_at = None

    def _prepare_authorize_flow(self, label: str) -> Tuple[Optional[str], Optional[str]]:
        """初始化当前阶段的授权流程，返回 device id 和 sentinel token。"""
        self._log(f"{label}: 先把会话热热身...")
        if not self._init_session():
            return None, None

        self._log(f"{label}: OAuth 流程准备开跑，系好鞋带...")
        if not self._start_oauth():
            return None, None

        self._log(f"{label}: 领取 Device ID 通行证...")
        did = self._get_device_id()
        if not did:
            return None, None

        self._log(f"{label}: 解一道 Sentinel POW 小题，答对才给进...")
        sen_token = self._check_sentinel(did)
        if not sen_token:
            return did, None

        self._log(f"{label}: Sentinel 点头放行，继续前进")
        return did, sen_token

    def _apply_token_info_to_result(self, result: RegistrationResult, token_info: Dict[str, Any]) -> None:
        result.account_id = str(token_info.get("account_id") or "")
        result.access_token = str(token_info.get("access_token") or "")
        result.refresh_token = str(token_info.get("refresh_token") or "")
        result.id_token = str(token_info.get("id_token") or "")
        result.password = self.password or ""
        result.source = "login" if self._is_existing_account else "register"

        session_token = str(
            token_info.get("session_token")
            or (self.session.cookies.get("__Secure-next-auth.session-token") if self.session else "")
            or ""
        )
        if session_token:
            self.session_token = session_token
            result.session_token = session_token
            self._log("Session Token 也捞到了，今天这网没白连")

    def _extract_session_via_api(self) -> Optional[Dict[str, Any]]:
        """直接调用 chatgpt.com session API，优先获取已落地的 token。"""
        if not self.session:
            return None

        try:
            default_headers = getattr(self.http_client, "default_headers", {}) or {}
            headers = {
                "accept": "application/json",
                "referer": "https://chatgpt.com/",
            }
            if default_headers.get("User-Agent"):
                headers["user-agent"] = default_headers["User-Agent"]

            response = self.session.get(
                "https://chatgpt.com/api/auth/session",
                headers=headers,
                timeout=15,
                allow_redirects=True,
            )
            self._log(f"Session API 状态: {response.status_code}")
            if response.status_code != 200:
                body_preview = (response.text or "")[:200]
                if body_preview:
                    self._log(f"Session API 响应: {body_preview}", "warning")
                return None

            try:
                data = response.json()
            except Exception as exc:
                self._log(f"Session API JSON 解析失败: {exc}", "warning")
                return None

            if not isinstance(data, dict):
                self._log("Session API 返回格式异常", "warning")
                return None

            access_token = str(data.get("accessToken") or "").strip()
            session_token = str(data.get("sessionToken") or "").strip()
            if not session_token and self.session:
                session_token = str(self.session.cookies.get("__Secure-next-auth.session-token") or "").strip()

            if not access_token:
                summary = json.dumps({key: data.get(key) for key in list(data.keys())[:6]}, ensure_ascii=False)
                self._log(f"Session API 未返回 accessToken，keys={list(data.keys())} summary={summary[:200]}", "warning")
                return None

            user_info = data.get("user") or {}
            account_info = data.get("account") or {}
            account_id = str(
                (user_info.get("id") if isinstance(user_info, dict) else "")
                or (account_info.get("id") if isinstance(account_info, dict) else "")
                or ""
            ).strip()
            self._log("Session API 已拿到 token，可直接收官")
            return {
                "account_id": account_id,
                "access_token": access_token,
                "refresh_token": "",
                "id_token": "",
                "session_token": session_token,
            }
        except Exception as exc:
            self._log(f"Session API 提取失败: {exc}", "warning")
            return None

    def _complete_token_exchange(self, result: RegistrationResult) -> bool:
        """在登录态已建立后，继续完成 workspace 和 OAuth token 获取。"""
        self._log("等待登录验证码到场，最后这位嘉宾还在路上...")
        code = self._get_verification_code()
        if not code:
            result.error_message = "获取验证码失败"
            return False

        self._log("核对登录验证码，验明正身一下...")
        if not self._validate_verification_code(code):
            result.error_message = "验证码校验失败"
            return False

        self._log("先问一下 ChatGPT 会话接口，看 token 有没有已经到手...")
        token_info = self._extract_session_via_api()
        if token_info:
            self._apply_token_info_to_result(result, token_info)
            return True

        otp_payload = self._last_otp_validation_payload or {}
        otp_page_type = str(((otp_payload.get("page") or {}).get("type")) or "").strip()
        otp_continue_url = self._auth_url(str(otp_payload.get("continue_url") or "").strip())
        if otp_page_type or otp_continue_url:
            self._log(
                "登录 OTP 校验后状态: "
                f"page={otp_page_type or 'unknown'}, "
                f"continue_url={otp_continue_url[:120] if otp_continue_url else 'none'}"
            )

        callback_url = None
        if otp_continue_url:
            callback_url = self._extract_callback_url(otp_continue_url)
            if not callback_url:
                self._log("顺着 OTP 返回的 continue_url 往前走，看看会不会直接给 callback...")
                callback_url = self._follow_redirects(otp_continue_url)
        if callback_url:
            self._log("OTP 后已经拿到 callback，直接处理 OAuth 回调...")
            token_info = self._handle_oauth_callback(callback_url)
            if not token_info:
                result.error_message = "处理 OAuth 回调失败"
                return False
            self._apply_token_info_to_result(result, token_info)
            return True

        if "add-phone" in otp_continue_url or otp_page_type == "add_phone":
            self._log("登录 OTP 后进入 add-phone，当前账号被要求补手机验证", "warning")
            result.error_message = "登录后进入 add-phone，当前流程无法直接获取 token"
            return False

        self._log("摸一下 Workspace ID，看看该坐哪桌...")
        workspace_id = self._get_workspace_id()
        if not workspace_id:
            extra = []
            if otp_page_type:
                extra.append(f"page={otp_page_type}")
            if otp_continue_url:
                extra.append(f"continue_url={otp_continue_url[:120]}")
            suffix = f"（{' | '.join(extra)}）" if extra else ""
            result.error_message = f"获取 Workspace ID 失败{suffix}"
            return False

        result.workspace_id = workspace_id

        self._log("选择 Workspace，安排个靠谱座位...")
        continue_url = self._select_workspace(workspace_id)
        if not continue_url:
            result.error_message = "选择 Workspace 失败"
            return False

        self._log("顺着重定向面包屑往前走，别跟丢了...")
        callback_url = self._extract_callback_url(continue_url) or self._follow_redirects(continue_url)
        if not callback_url:
            result.error_message = "跟随重定向链失败"
            return False

        self._log("处理 OAuth 回调，准备把 token 请出来...")
        token_info = self._handle_oauth_callback(callback_url)
        if not token_info:
            result.error_message = "处理 OAuth 回调失败"
            return False
        self._apply_token_info_to_result(result, token_info)
        return True

    def _restart_login_flow(self) -> Tuple[bool, str]:
        """新注册账号完成建号后，重新发起一次登录流程拿 token。"""
        self._token_acquisition_requires_login = True
        self._log("注册这边忙完了，再走一趟登录把 token 请出来，收个尾...")
        self._reset_auth_flow()

        did, sen_token = self._prepare_authorize_flow("重新登录")
        if not did:
            return False, "重新登录时获取 Device ID 失败"
        if not sen_token:
            return False, "重新登录时 Sentinel POW 验证失败"

        login_start_result = self._submit_login_start(did, sen_token)
        if not login_start_result.success:
            return False, f"重新登录提交邮箱失败: {login_start_result.error_message}"
        if login_start_result.page_type != OPENAI_PAGE_TYPES["LOGIN_PASSWORD"]:
            return False, f"重新登录未进入密码页面: {login_start_result.page_type or 'unknown'}"

        password_result = self._submit_login_password()
        if not password_result.success:
            return False, f"重新登录提交密码失败: {password_result.error_message}"
        if not password_result.is_existing_account:
            return False, f"重新登录未进入验证码页面: {password_result.page_type or 'unknown'}"
        return True, ""

    def _register_password(self) -> Tuple[bool, Optional[str]]:
        """注册密码"""
        try:
            # 生成密码
            password = self._generate_password()
            self.password = password  # 保存密码到实例变量
            self._log(f"生成密码: {password}")
            did = self._device_id or self.session.cookies.get("oai-did")
            if not did:
                self._log("提交密码前缺少 Device ID", "error")
                return False, None
            sen_token = self._check_sentinel(did, flow="authorize_continue")
            if not sen_token:
                self._log("提交密码前 Sentinel POW 验证失败", "error")
                return False, None

            # 提交密码注册
            register_body = json.dumps({
                "password": password,
                "username": self.email
            })
            headers = self._build_openai_json_headers("https://auth.openai.com/create-account/password")
            headers["openai-sentinel-token"] = self.http_client.build_sentinel_header(
                device_id=did,
                flow="authorize_continue",
                token=sen_token,
            )

            response = self.session.post(
                OPENAI_API_ENDPOINTS["register"],
                headers=headers,
                data=register_body,
            )

            self._log(f"提交密码状态: {response.status_code}")

            if response.status_code != 200:
                error_text = response.text[:500]
                self._log(f"密码注册失败: {error_text}", "warning")

                # 解析错误信息，判断是否是邮箱已注册
                try:
                    error_json = response.json()
                    error_msg = error_json.get("error", {}).get("message", "")
                    error_code = error_json.get("error", {}).get("code", "")

                    # 检测邮箱已注册的情况
                    if "already" in error_msg.lower() or "exists" in error_msg.lower() or error_code == "user_exists":
                        self._log(f"邮箱 {self.email} 可能已在 OpenAI 注册过", "error")
                        # 标记此邮箱为已注册状态
                        self._mark_email_as_registered()
                except Exception:
                    pass

                return False, None

            return True, password

        except Exception as e:
            self._log(f"密码注册失败: {e}", "error")
            return False, None

    def _mark_email_as_registered(self):
        """标记邮箱为已注册状态（用于防止重复尝试）"""
        try:
            with get_db() as db:
                # 检查是否已存在该邮箱的记录
                existing = crud.get_account_by_email(db, self.email)
                if not existing:
                    # 创建一个失败记录，标记该邮箱已注册过
                    crud.create_account(
                        db,
                        email=self.email,
                        password="",  # 空密码表示未成功注册
                        email_service=self.email_service.service_type.value,
                        email_service_id=self.email_info.get("service_id") if self.email_info else None,
                        status="failed",
                        extra_data={"register_failed_reason": "email_already_registered_on_openai"}
                    )
                    self._log(f"已在数据库中标记邮箱 {self.email} 为已注册状态")
        except Exception as e:
            logger.warning(f"标记邮箱状态失败: {e}")

    def _send_verification_code(self) -> bool:
        """发送验证码"""
        try:
            # 记录发送时间戳
            self._otp_sent_at = time.time()

            response = self.session.get(
                OPENAI_API_ENDPOINTS["send_otp"],
                headers=self._build_openai_json_headers("https://auth.openai.com/create-account/password"),
            )

            self._log(f"验证码发送状态: {response.status_code}")
            return response.status_code == 200

        except Exception as e:
            self._log(f"发送验证码失败: {e}", "error")
            return False

    def _get_verification_code(self) -> Optional[str]:
        """获取验证码"""
        try:
            self._log(f"正在等待邮箱 {self.email} 的验证码...")

            email_id = self.email_info.get("service_id") if self.email_info else None
            code = self.email_service.get_verification_code(
                email=self.email,
                email_id=email_id,
                timeout=30,
                pattern=OTP_CODE_PATTERN,
                otp_sent_at=self._otp_sent_at,
            )

            if code:
                self._log(f"成功获取验证码: {code}")
                return code
            else:
                self._log("等待验证码超时", "error")
                return None

        except Exception as e:
            self._log(f"获取验证码失败: {e}", "error")
            return None

    def _build_openai_json_headers(self, referer: str) -> Dict[str, str]:
        """构造 OpenAI JSON 请求头。"""
        headers = {
            "referer": referer,
            "origin": "https://auth.openai.com",
            "accept": "application/json",
            "content-type": "application/json",
        }

        default_headers = getattr(self.http_client, "default_headers", {}) or {}
        if default_headers.get("User-Agent"):
            headers["user-agent"] = default_headers["User-Agent"]
        if default_headers.get("Accept-Language"):
            headers["accept-language"] = default_headers["Accept-Language"]
        if default_headers.get("sec-ch-ua"):
            headers["sec-ch-ua"] = default_headers["sec-ch-ua"]
        if default_headers.get("sec-ch-ua-mobile"):
            headers["sec-ch-ua-mobile"] = default_headers["sec-ch-ua-mobile"]
        if default_headers.get("sec-ch-ua-platform"):
            headers["sec-ch-ua-platform"] = default_headers["sec-ch-ua-platform"]

        did = self._device_id or (self.session.cookies.get("oai-did") if self.session else None)
        if did:
            headers["oai-device-id"] = did

        return headers

    @staticmethod
    def _auth_url(url: str) -> str:
        candidate = str(url or "").strip()
        if not candidate:
            return ""
        return urllib.parse.urljoin("https://auth.openai.com", candidate)

    def _extract_callback_url(self, value: str) -> Optional[str]:
        candidate = self._auth_url(value)
        if not candidate:
            return None
        parsed = urllib.parse.urlparse(candidate)
        query = urllib.parse.parse_qs(parsed.query, keep_blank_values=True)
        code = str((query.get("code") or [""])[0] or "").strip()
        state = str((query.get("state") or [""])[0] or "").strip()
        if code and state:
            return candidate
        return None

    def _validate_verification_code(self, code: str) -> bool:
        """验证验证码"""
        try:
            self._last_otp_validation_payload = {}
            code_body = f'{{"code":"{code}"}}'

            response = self.session.post(
                OPENAI_API_ENDPOINTS["validate_otp"],
                headers=self._build_openai_json_headers("https://auth.openai.com/email-verification"),
                data=code_body,
            )

            self._log(f"验证码校验状态: {response.status_code}")
            if response.status_code == 200:
                try:
                    payload = response.json()
                    if isinstance(payload, dict):
                        self._last_otp_validation_payload = payload
                except Exception:
                    self._last_otp_validation_payload = {}
            return response.status_code == 200

        except Exception as e:
            self._log(f"验证验证码失败: {e}", "error")
            return False

    def _create_user_account(self) -> bool:
        """创建用户账户"""
        try:
            user_info = generate_random_user_info()
            self._log(f"生成用户信息: {user_info['name']}, 生日: {user_info['birthdate']}")
            create_account_body = json.dumps(user_info)
            did = self._device_id or self.session.cookies.get("oai-did")
            if not did:
                self._log("创建账户前缺少 Device ID", "error")
                return False
            sen_token = self._check_sentinel(did, flow="authorize_continue")
            if not sen_token:
                self._log("创建账户前 Sentinel POW 验证失败", "error")
                return False
            headers = self._build_openai_json_headers("https://auth.openai.com/about-you")
            headers["openai-sentinel-token"] = self.http_client.build_sentinel_header(
                device_id=did,
                flow="authorize_continue",
                token=sen_token,
            )

            response = self.session.post(
                OPENAI_API_ENDPOINTS["create_account"],
                headers=headers,
                data=create_account_body,
            )

            self._log(f"账户创建状态: {response.status_code}")

            if response.status_code != 200:
                self._log(f"账户创建失败: {response.text[:200]}", "warning")
                return False

            return True

        except Exception as e:
            self._log(f"创建账户失败: {e}", "error")
            return False

    def _get_workspace_id(self) -> Optional[str]:
        """获取 Workspace ID"""
        try:
            auth_cookie = self.session.cookies.get("oai-client-auth-session")
            if not auth_cookie:
                self._log("未能获取到授权 Cookie", "error")
                return None

            # 解码 JWT
            import base64
            import json as json_module

            try:
                segments = auth_cookie.split(".")
                if len(segments) < 1:
                    self._log("授权 Cookie 格式错误", "error")
                    return None

                # 解码第一个 segment
                payload = segments[0]
                pad = "=" * ((4 - (len(payload) % 4)) % 4)
                decoded = base64.urlsafe_b64decode((payload + pad).encode("ascii"))
                auth_json = json_module.loads(decoded.decode("utf-8"))

                workspaces = auth_json.get("workspaces") or []
                if not workspaces:
                    self._log("授权 Cookie 里没有 workspace 信息", "error")
                    return None

                workspace_id = str((workspaces[0] or {}).get("id") or "").strip()
                if not workspace_id:
                    self._log("无法解析 workspace_id", "error")
                    return None

                self._log(f"Workspace ID: {workspace_id}")
                return workspace_id

            except Exception as e:
                self._log(f"解析授权 Cookie 失败: {e}", "error")
                return None

        except Exception as e:
            self._log(f"获取 Workspace ID 失败: {e}", "error")
            return None

    def _select_workspace(self, workspace_id: str) -> Optional[str]:
        """选择 Workspace"""
        try:
            select_body = f'{{"workspace_id":"{workspace_id}"}}'

            response = self.session.post(
                OPENAI_API_ENDPOINTS["select_workspace"],
                headers={
                    "referer": "https://auth.openai.com/sign-in-with-chatgpt/codex/consent",
                    "content-type": "application/json",
                },
                data=select_body,
            )

            if response.status_code != 200:
                self._log(f"选择 workspace 失败: {response.status_code}", "error")
                self._log(f"响应: {response.text[:200]}", "warning")
                return None

            continue_url = str((response.json() or {}).get("continue_url") or "").strip()
            if not continue_url:
                self._log("workspace/select 响应里缺少 continue_url", "error")
                return None

            self._log(f"Continue URL: {continue_url[:100]}...")
            return continue_url

        except Exception as e:
            self._log(f"选择 Workspace 失败: {e}", "error")
            return None

    def _follow_redirects(self, start_url: str) -> Optional[str]:
        """跟随重定向链，寻找回调 URL"""
        try:
            current_url = self._auth_url(start_url)
            max_redirects = 6

            direct_callback = self._extract_callback_url(current_url)
            if direct_callback:
                self._log(f"起始 URL 已经是回调地址: {direct_callback[:100]}...")
                return direct_callback

            for i in range(max_redirects):
                self._log(f"重定向 {i+1}/{max_redirects}: {current_url[:100]}...")

                response = self.session.get(
                    current_url,
                    allow_redirects=False,
                    timeout=15
                )

                location = response.headers.get("Location") or ""

                # 如果不是重定向状态码，停止
                if response.status_code not in [301, 302, 303, 307, 308]:
                    self._log(f"非重定向状态码: {response.status_code}")
                    break

                if not location:
                    self._log("重定向响应缺少 Location 头")
                    break

                # 构建下一个 URL
                next_url = urllib.parse.urljoin(current_url, location)

                # 检查是否包含回调参数
                callback_url = self._extract_callback_url(next_url)
                if callback_url:
                    self._log(f"找到回调 URL: {callback_url[:100]}...")
                    return callback_url

                current_url = next_url

            self._log("未能在重定向链中找到回调 URL", "error")
            return None

        except Exception as e:
            self._log(f"跟随重定向失败: {e}", "error")
            return None

    def _handle_oauth_callback(self, callback_url: str) -> Optional[Dict[str, Any]]:
        """处理 OAuth 回调"""
        try:
            if not self.oauth_start:
                self._log("OAuth 流程未初始化", "error")
                return None

            self._log("处理 OAuth 回调，最后一哆嗦，稳住别抖...")
            token_info = self.oauth_manager.handle_callback(
                callback_url=callback_url,
                expected_state=self.oauth_start.state,
                code_verifier=self.oauth_start.code_verifier
            )

            self._log("OAuth 授权成功，通关文牒到手")
            return token_info

        except Exception as e:
            self._log(f"处理 OAuth 回调失败: {e}", "error")
            return None

    def run(self) -> RegistrationResult:
        """
        执行完整的注册流程

        支持已注册账号自动登录：
        - 如果检测到邮箱已注册，自动切换到登录流程
        - 已注册账号跳过：设置密码、发送验证码、创建用户账户
        - 共用步骤：获取验证码、验证验证码、Workspace 和 OAuth 回调

        Returns:
            RegistrationResult: 注册结果
        """
        result = RegistrationResult(success=False, logs=self.logs)

        try:
            self._is_existing_account = False
            self._token_acquisition_requires_login = False
            self._otp_sent_at = None

            self._log("=" * 60)
            self._log("注册流程启动，开始替你敲门")
            self._log("=" * 60)

            # 1. 检查 IP 地理位置
            self._log("1. 先看看这条网络从哪儿来，别一开局就站错片场...")
            ip_ok, location = self._check_ip_location()
            if not ip_ok:
                result.error_message = f"IP 地理位置不支持: {location}"
                self._log(f"IP 检查失败: {location}", "error")
                return result

            self._log(f"IP 位置: {location}")

            # 2. 创建邮箱
            self._log("2. 开个新邮箱，准备收信...")
            if not self._create_email():
                result.error_message = "创建邮箱失败"
                return result

            result.email = self.email

            # 3. 准备首轮授权流程
            did, sen_token = self._prepare_authorize_flow("首次授权")
            if not did:
                result.error_message = "获取 Device ID 失败"
                return result
            if not sen_token:
                result.error_message = "Sentinel POW 验证失败"
                return result

            # 4. 提交注册入口邮箱
            self._log("4. 递上邮箱，看看 OpenAI 这球怎么接...")
            signup_result = self._submit_signup_form(did, sen_token)
            if not signup_result.success:
                result.error_message = f"提交注册表单失败: {signup_result.error_message}"
                return result

            if self._is_existing_account:
                self._log("检测到这是老朋友账号，直接切去登录拿 token，不走弯路")
            else:
                self._log("5. 设置密码，别让小偷偷笑...")
                password_ok, _ = self._register_password()
                if not password_ok:
                    result.error_message = "注册密码失败"
                    return result

                self._log("6. 催一下注册验证码出门，邮差该冲刺了...")
                if not self._send_verification_code():
                    result.error_message = "发送验证码失败"
                    return result

                self._log("7. 等验证码飞来，邮箱请注意查收...")
                code = self._get_verification_code()
                if not code:
                    result.error_message = "获取验证码失败"
                    return result

                self._log("8. 对一下验证码，看看是不是本人...")
                if not self._validate_verification_code(code):
                    result.error_message = "验证验证码失败"
                    return result

                self._log("9. 给账号办个正式户口，名字写档案里...")
                if not self._create_user_account():
                    result.error_message = "创建用户账户失败"
                    return result

                login_ready, login_error = self._restart_login_flow()
                if not login_ready:
                    result.error_message = login_error
                    return result

            if not self._complete_token_exchange(result):
                return result

            # 10. 完成
            self._log("=" * 60)
            if self._is_existing_account:
                self._log("登录成功，老朋友顺利回家")
            else:
                self._log("注册成功，账号已经稳稳落地，可以开香槟了")
            self._log(f"邮箱: {result.email}")
            self._log(f"Account ID: {result.account_id}")
            self._log(f"Workspace ID: {result.workspace_id}")
            self._log("=" * 60)

            result.success = True
            result.metadata = {
                "email_service": self.email_service.service_type.value,
                "proxy_used": self.proxy_url,
                "registered_at": datetime.now().isoformat(),
                "is_existing_account": self._is_existing_account,
                "token_acquired_via_relogin": self._token_acquisition_requires_login,
            }

            return result

        except Exception as e:
            self._log(f"注册过程中发生未预期错误: {e}", "error")
            result.error_message = str(e)
            return result

    def save_to_database(self, result: RegistrationResult) -> bool:
        """
        保存注册结果到数据库

        Args:
            result: 注册结果

        Returns:
            是否保存成功
        """
        if not result.success:
            return False

        try:
            # 获取默认 client_id
            settings = get_settings()

            with get_db() as db:
                # 保存账户信息
                account = crud.create_account(
                    db,
                    email=result.email,
                    password=result.password,
                    client_id=settings.openai_client_id,
                    session_token=result.session_token,
                    email_service=self.email_service.service_type.value,
                    email_service_id=self.email_info.get("service_id") if self.email_info else None,
                    account_id=result.account_id,
                    workspace_id=result.workspace_id,
                    access_token=result.access_token,
                    refresh_token=result.refresh_token,
                    id_token=result.id_token,
                    proxy_used=self.proxy_url,
                    extra_data=result.metadata,
                    source=result.source
                )

                self._log(f"账户已存进数据库，落袋为安，ID: {account.id}")
                return True

        except Exception as e:
            self._log(f"保存到数据库失败: {e}", "error")
            return False
