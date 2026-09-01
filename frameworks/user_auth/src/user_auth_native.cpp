/*
 * Copyright (c) 2022 Huawei Device Co., Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include "user_auth_native.h"
#include <charconv>
#include <cinttypes>
#include <if_system_ability_manager.h>
#include <iservice_registry.h>
#include <string>
#include <system_ability_definition.h>
#include <system_error>
#ifdef SUPPORT_SURFACE
#include "face_auth_innerkit.h"
#include "surface.h"
#include "surface_utils.h"
#endif
#include "system_ability_definition.h"
#include "userauth_hilog_wrapper.h"

namespace OHOS {
namespace UserIAM {
namespace UserAuth {
sptr<IUserAuth> UserAuthNative::GetProxy()
{
    USERAUTH_HILOGD(MODULE_INNERKIT, "GetProxy start");
    std::lock_guard lock(mutex_);
    if (proxy_ != nullptr) {
        return proxy_;
    }
    sptr<ISystemAbilityManager> sam = SystemAbilityManagerClient::GetInstance().GetSystemAbilityManager();
    if (sam == nullptr) {
        USERAUTH_HILOGE(MODULE_INNERKIT, "Failed to get system manager");
        return nullptr;
    }
    sptr<IRemoteObject> obj = sam->CheckSystemAbility(SUBSYS_USERIAM_SYS_ABILITY_USERAUTH);
    if (obj == nullptr) {
        USERAUTH_HILOGE(MODULE_INNERKIT, "Failed to get userauth service");
        return nullptr;
    }
    sptr<IRemoteObject::DeathRecipient> dr = new UserAuthDeathRecipient();
    if ((obj->IsProxyObject()) && (!obj->AddDeathRecipient(dr))) {
        USERAUTH_HILOGE(MODULE_INNERKIT, "Failed to add death recipient");
        return nullptr;
    }

    proxy_ = iface_cast<IUserAuth>(obj);
    deathRecipient_ = dr;
    USERAUTH_HILOGI(MODULE_INNERKIT, "Succeed to connect userauth service");
    return proxy_;
}

void UserAuthNative::ResetProxy(const wptr<IRemoteObject> &remote)
{
    USERAUTH_HILOGD(MODULE_INNERKIT, "ResetProxy start");
    std::lock_guard<std::mutex> lock(mutex_);
    if (proxy_ == nullptr) {
        return;
    }

    auto serviceRemote = proxy_->AsObject();
    if ((serviceRemote != nullptr) && (serviceRemote == remote.promote())) {
        serviceRemote->RemoveDeathRecipient(deathRecipient_);
        proxy_ = nullptr;
    }
}

void UserAuthNative::UserAuthDeathRecipient::OnRemoteDied(const wptr<IRemoteObject> &remote)
{
    USERAUTH_HILOGD(MODULE_INNERKIT, "OnRemoteDied start");
    if (remote == nullptr) {
        USERAUTH_HILOGE(MODULE_INNERKIT, "OnRemoteDied failed, remote is nullptr");
        return;
    }

    UserAuthNative::GetInstance().ResetProxy(remote);
}

int32_t UserAuthNative::GetAvailableStatus(const AuthType authType, const AuthTrustLevel authTrustLevel)
{
    USERAUTH_HILOGD(MODULE_INNERKIT, "GetAvailableStatus start");
    auto proxy = GetProxy();
    if (proxy == nullptr) {
        return E_RET_NOSERVER;
    }

    return proxy->GetAvailableStatus(authType, authTrustLevel);
}

void UserAuthNative::GetProperty(const GetPropertyRequest &request, std::shared_ptr<GetPropCallback> callback)
{
    USERAUTH_HILOGD(MODULE_INNERKIT, "GetProperty start");
    if (callback == nullptr) {
        USERAUTH_HILOGE(MODULE_INNERKIT, "GetProperty callback is nullptr");
        return;
    }
    auto proxy = GetProxy();
    if (proxy == nullptr) {
        ExecutorProperty result = {};
        result.result = E_RET_NOSERVER;
        callback->onGetProperty(result);
        return;
    }
    sptr<IUserAuthCallback> asyncStub = new (std::nothrow) UserAuthAsyncStub(callback);
    if (asyncStub == nullptr) {
        USERAUTH_HILOGE(MODULE_INNERKIT, "GetProperty asyncStub is nullptr");
        return;
    }
    proxy->GetProperty(request, asyncStub);
}

void UserAuthNative::GetProperty(const int32_t userId, const GetPropertyRequest &request,
    std::shared_ptr<GetPropCallback> callback)
{
    USERAUTH_HILOGD(MODULE_INNERKIT, "GetProperty start");
    if (callback == nullptr) {
        USERAUTH_HILOGE(MODULE_INNERKIT, "GetProperty callback is nullptr");
        return;
    }
    auto proxy = GetProxy();
    if (proxy == nullptr) {
        ExecutorProperty result = {};
        result.result = E_RET_NOSERVER;
        callback->onGetProperty(result);
        return;
    }
    sptr<IUserAuthCallback> asyncStub = new (std::nothrow) UserAuthAsyncStub(callback);
    if (asyncStub == nullptr) {
        USERAUTH_HILOGE(MODULE_INNERKIT, "GetProperty asyncStub is nullptr");
        return;
    }
    proxy->GetProperty(userId, request, asyncStub);
}

#ifdef SUPPORT_SURFACE
namespace {
bool ParseSurfaceId(const std::string &text, uint64_t &out)
{
    if (text.empty()) {
        return false;
    }
    uint64_t value = 0;
    const char *first = text.data();
    const char *last = first + text.size();
    auto [ptr, ec] = std::from_chars(first, last, value);
    if (ec != std::errc() || ptr != last) {
        return false;
    }
    out = value;
    return true;
}
}

int32_t UserAuthNative::SetSurfaceId(const SetPropertyRequest &request)
{
    std::string surfaceIdString(request.setInfo.begin(), request.setInfo.end());
    uint64_t surfaceId = 0;
    if (!ParseSurfaceId(surfaceIdString, surfaceId)) {
        USERAUTH_HILOGE(MODULE_JS_NAPI, "SetSurfaceId invalid surface id");
        return GENERAL_ERROR;
    }
    USERAUTH_HILOGI(MODULE_JS_NAPI, "SetSurfaceId string %{public}s converted int %{public}" PRIu64,
        surfaceIdString.c_str(), surfaceId);
    if (surfaceId == 0) {
        int32_t ret = FaceAuth::FaceAuthInnerKit::SetBufferProducer(nullptr);
        USERAUTH_HILOGE(MODULE_JS_NAPI, "SetBufferProducer null result %{public}d", ret);
        return ret;
    }

    sptr<Surface> previewSurface = SurfaceUtils::GetInstance()->GetSurface(surfaceId);
    if (previewSurface == nullptr) {
        USERAUTH_HILOGE(MODULE_JS_NAPI, "GetXComponentSurfaceById Failed!");
        return GENERAL_ERROR;
    }

    sptr<IBufferProducer> bufferProducer = previewSurface->GetProducer();
    if (bufferProducer == nullptr) {
        USERAUTH_HILOGE(MODULE_JS_NAPI, "GetProducer Failed!");
        return GENERAL_ERROR;
    }

    int32_t ret = FaceAuth::FaceAuthInnerKit::SetBufferProducer(bufferProducer);
    USERAUTH_HILOGI(MODULE_JS_NAPI, "SetBufferProducer result %{public}d", ret);
    return ret;
}
#else
int32_t UserAuthNative::SetSurfaceId(const SetPropertyRequest &request)
{
    USERAUTH_HILOGE(MODULE_JS_NAPI, "surface is not supported!");
    return GENERAL_ERROR;
}
#endif

void UserAuthNative::SetProperty(const SetPropertyRequest &request, std::shared_ptr<SetPropCallback> callback)
{
    USERAUTH_HILOGD(MODULE_INNERKIT, "SetProperty start");
    if (callback == nullptr) {
        USERAUTH_HILOGE(MODULE_INNERKIT, "SetProperty callback is nullptr");
        return;
    }
    auto proxy = GetProxy();
    if (proxy == nullptr) {
        callback->onSetProperty(E_RET_NOSERVER);
        return;
    }
    sptr<IUserAuthCallback> asyncStub = new (std::nothrow) UserAuthAsyncStub(callback);
    if (asyncStub == nullptr) {
        USERAUTH_HILOGE(MODULE_INNERKIT, "SetProperty asyncStub is nullptr");
        return;
    }
    if (request.key == static_cast<uint32_t>(AuthPropertyMode::PROPERMODE_SET_SURFACE_ID)
        && request.authType == FACE) {
        asyncStub->onSetExecutorProperty(SetSurfaceId(request));
    } else {
        proxy->SetProperty(request, asyncStub);
    }
    USERAUTH_HILOGD(MODULE_INNERKIT, "SetProperty end");
}

uint64_t UserAuthNative::Auth(const uint64_t challenge, const AuthType authType, const AuthTrustLevel authTrustLevel,
    std::shared_ptr<UserAuthCallback> callback)
{
    USERAUTH_HILOGD(MODULE_INNERKIT, "Auth start");
    if (callback == nullptr) {
        USERAUTH_HILOGE(MODULE_INNERKIT, "Auth callback is nullptr");
        return INVALID_PARAMETERS;
    }
    auto proxy = GetProxy();
    if (proxy == nullptr) {
        return E_RET_NOSERVER;
    }
    sptr<IUserAuthCallback> asyncStub = new (std::nothrow) UserAuthAsyncStub(callback);
    if (asyncStub == nullptr) {
        USERAUTH_HILOGE(MODULE_INNERKIT, "Auth asyncStub is nullptr");
        return GENERAL_ERROR;
    }
    return proxy->Auth(challenge, authType, authTrustLevel, asyncStub);
}

uint64_t UserAuthNative::AuthUser(const int32_t userId, const uint64_t challenge, const AuthType authType,
    const AuthTrustLevel authTrustLevel, std::shared_ptr<UserAuthCallback> callback)
{
    USERAUTH_HILOGD(MODULE_INNERKIT, "AuthUser start");
    if (callback == nullptr) {
        USERAUTH_HILOGE(MODULE_INNERKIT, "AuthUser callback is nullptr");
        return INVALID_PARAMETERS;
    }
    auto proxy = GetProxy();
    if (proxy == nullptr) {
        return E_RET_NOSERVER;
    }
    sptr<IUserAuthCallback> asyncStub = new (std::nothrow) UserAuthAsyncStub(callback);
    if (asyncStub == nullptr) {
        USERAUTH_HILOGE(MODULE_INNERKIT, "AuthUser asyncStub is nullptr");
        return GENERAL_ERROR;
    }
    return proxy->AuthUser(userId, challenge, authType, authTrustLevel, asyncStub);
}

int32_t UserAuthNative::CancelAuth(const uint64_t contextId)
{
    USERAUTH_HILOGD(MODULE_INNERKIT, "CancelAuth start");
    auto proxy = GetProxy();
    if (proxy == nullptr) {
        return E_RET_NOSERVER;
    }

    return proxy->CancelAuth(contextId);
}

int32_t UserAuthNative::GetVersion()
{
    USERAUTH_HILOGD(MODULE_INNERKIT, "GetVersion start");
    auto proxy = GetProxy();
    if (proxy == nullptr) {
        return INVALID_PARAMETERS;
    }

    return proxy->GetVersion();
}
} // namespace UserAuth
} // namespace UserIAM
} // namespace OHOS
