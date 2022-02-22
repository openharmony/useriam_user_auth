/*
 * Copyright (c) 2021 Huawei Device Co., Ltd.
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

#include <file_ex.h>
#include <string_ex.h>
#include "userauth_hilog_wrapper.h"
#include "useriam_common.h"
#include "accesstoken_kit.h"
#include "userauth_service.h"

namespace OHOS {
namespace UserIAM {
namespace UserAuth {
const static int AUTHTURSTLEVEL_SYS = 1;

REGISTER_SYSTEM_ABILITY_BY_ID(UserAuthService, SUBSYS_USERIAM_SYS_ABILITY_USERAUTH, true);

UserAuthService::UserAuthService(int32_t systemAbilityId, bool runOnCreate)
    : SystemAbility(systemAbilityId, runOnCreate)
{
}

UserAuthService::~UserAuthService()
{
}

void UserAuthService::OnStart()
{
    USERAUTH_HILOGD(MODULE_SERVICE, "Start service");
    if (!Publish(this)) {
        USERAUTH_HILOGE(MODULE_SERVICE, "Failed to publish service");
    }
    ContextThreadPool::GetInstance().Start(THREADPOOLMAXSTART);
    ContextThreadPool::GetInstance().SetMaxTaskNum(THREADPOOLMAXSTART);
    bool ret = OHOS::UserIAM::Common::IsIAMInited();
    if (!ret) {
        OHOS::UserIAM::Common::Init();
    }
}

void UserAuthService::OnStop()
{
    USERAUTH_HILOGD(MODULE_SERVICE, "Stop service");
    ContextThreadPool::GetInstance().Stop();
    bool ret = OHOS::UserIAM::Common::IsIAMInited();
    if (ret) {
        int32_t iret = OHOS::UserIAM::Common::Close();
        if (iret != SUCCESS) {
            USERAUTH_HILOGE(MODULE_SERVICE, "Failed to Stop service");
        }
    }
}

int32_t UserAuthService::GetAvailableStatus(const AuthType authType, const AuthTurstLevel authTurstLevel)
{
    USERAUTH_HILOGD(MODULE_SERVICE, "UserAuthService GetAvailableStatus is start");
    int ret = GENERAL_ERROR;
    int result = TRUST_LEVEL_NOT_SUPPORT;
    int32_t userID = 0;
    uint32_t authTurstLevelFromSys = AUTHTURSTLEVEL_SYS;
    if (authTurstLevel > ATL4 || authTurstLevel < ATL1) {
        USERAUTH_HILOGE(MODULE_SERVICE, "UserAuthService GetAvailableStatus AuthTurstLevel is NOT SUPPORT!");
        return result;
    }

    ret = this->GetCallingUserID(userID);
    if (ret != SUCCESS) {
        USERAUTH_HILOGE(MODULE_SERVICE, "UserAuthService GetAvailableStatus GetUserID is ERROR!");
        return result;
    }

    ret = userauthController_.GetAuthTrustLevel(userID, authType, authTurstLevelFromSys);
    if (ret == SUCCESS) {
        USERAUTH_HILOGD(MODULE_SERVICE, "UserAuthService  iAuthTurstLevel_:%{public}u", authTurstLevelFromSys);
        USERAUTH_HILOGD(MODULE_SERVICE, "UserAuthService  authTurstLevel:%{public}u", authTurstLevel);
        if (authTurstLevelFromSys < authTurstLevel) {
            USERAUTH_HILOGE(MODULE_SERVICE, "UserAuthService authTurstLevel is ERROR!");
            return result;
        }
    }

    return ret;
}

void UserAuthService::GetProperty(const GetPropertyRequest request, sptr<IUserAuthCallback>& callback)
{
    USERAUTH_HILOGD(MODULE_SERVICE, "UserAuthService GetProperty is start");
    uint64_t callerID = 0;
    std::string callerName;
    if (callback == nullptr) {
        USERAUTH_HILOGE(MODULE_SERVICE, "UserAuthService GetProperty IUserAuthCallback is NULL!");
        return;
    }
    int32_t userID = 0;

    int32_t ret = this->GetCallingUserID(userID);
    if (ret != SUCCESS) {
        AuthResult extraInfo;
        callback->onResult(ret, extraInfo);
        return;
    }

    sptr<IRemoteObject::DeathRecipient> dr = new UserAuthServiceCallbackDeathRecipient(callback);
    if ((!callback->AsObject()->AddDeathRecipient(dr))) {
        USERAUTH_HILOGE(MODULE_SERVICE, "Failed to add death recipient UserAuthServiceCallbackDeathRecipient");
    }

    callerID = this->GetCallingUid();
    callerName = std::to_string(callerID);

    userauthController_.GetPropAuthInfo(userID, callerName, callerID, request, callback);
}

void UserAuthService::SetProperty(const SetPropertyRequest request, sptr<IUserAuthCallback>& callback)
{
    USERAUTH_HILOGD(MODULE_SERVICE, "UserAuthService SetProperty is start");
    int ret = GENERAL_ERROR;
    uint64_t callerID = 0;
    std::string callerName = "";
    if (callback == nullptr) {
        USERAUTH_HILOGE(MODULE_SERVICE, "UserAuthService SetProperty IUserAuthCallback is NULL!");
        return;
    }

    sptr<IRemoteObject::DeathRecipient> dr = new UserAuthServiceCallbackDeathRecipient(callback);
    if ((!callback->AsObject()->AddDeathRecipient(dr))) {
        USERAUTH_HILOGE(MODULE_SERVICE, "Failed to add death recipient UserAuthServiceCallbackDeathRecipient");
    }

    callerID = this->GetCallingUid();
    callerName = std::to_string(callerID);

    ret = userauthController_.SetExecutorProp(callerID, callerName, request, callback);
    if (ret != SUCCESS) {
        USERAUTH_HILOGE(MODULE_SERVICE, "UserAuthService SetExecutorProp getUserID is ERROR!");
        callback->onSetExecutorProperty(ret);
        return;
    }
}

int32_t UserAuthService::GetCallingUserID(int32_t &userID)
{
    uint32_t tokenID = this->GetFirstTokenID();
    if (tokenID == 0) {
        tokenID = this->GetCallingTokenID();
    }
    Security::AccessToken::ATokenTypeEnum callingType = Security::AccessToken::AccessTokenKit::GetTokenType(tokenID);
    if (callingType != Security::AccessToken::TOKEN_HAP) {
        USERAUTH_HILOGE(MODULE_SERVICE, "CallingType is not hap.");
        return TYPE_NOT_SUPPORT;
    }
    Security::AccessToken::HapTokenInfo hapTokenInfo;
    int result = Security::AccessToken::AccessTokenKit::GetHapTokenInfo(tokenID, hapTokenInfo);
    if (result != SUCCESS) {
        USERAUTH_HILOGE(MODULE_SERVICE, "Get hap token info failed.");
        return TYPE_NOT_SUPPORT;
    }
    userID = (int32_t)hapTokenInfo.userID;
    USERAUTH_HILOGE(MODULE_SERVICE, "GetCallingUserID is %{public}d", userID);
    return SUCCESS;
}

uint64_t UserAuthService::Auth(const uint64_t challenge, const AuthType authType,
                               const AuthTurstLevel authTurstLevel,
                               sptr<IUserAuthCallback>& callback)
{
    USERAUTH_HILOGD(MODULE_SERVICE, "UserAuthService Auth is start");
    int ret = SUCCESS;
    int result = SUCCESS;
    int32_t userID = 0;
    uint64_t callerID = 0;
    std::string callerName = "";
    uint64_t contextID = 0;
    AuthSolution authSolutionParam;
    CoAuthInfo coAuthInfo;
    AuthResult extraInfo;

    sptr<IRemoteObject::DeathRecipient> dr = new UserAuthServiceCallbackDeathRecipient(callback);
    if ((!callback->AsObject()->AddDeathRecipient(dr))) {
        USERAUTH_HILOGE(MODULE_SERVICE, "Failed to add death recipient UserAuthServiceCallbackDeathRecipient");
    }

    if (GetControllerData(callback, extraInfo, authTurstLevel, callerID, callerName, contextID) == FAIL) {
        return ret;
    }
    result = this->GetCallingUserID(userID);
    if (result != SUCCESS) {
        USERAUTH_HILOGE(MODULE_SERVICE, "UserAuthService Auth GetUserID is ERROR!");
        callback->onResult(FAIL, extraInfo);
        return ret;
    }

    authSolutionParam.contextId = contextID;
    authSolutionParam.userId = userID;
    authSolutionParam.authTrustLevel = authTurstLevel;
    authSolutionParam.challenge = challenge;
    authSolutionParam.authType = authType;
    result = userauthController_.GenerateSolution(authSolutionParam, coAuthInfo.sessionIds);
    if (result != SUCCESS) {
        USERAUTH_HILOGE(MODULE_SERVICE, "UserAuthService Auth GenerateSolution is ERROR!");
        callback->onResult(result, extraInfo);
        return ret;
    }

    coAuthInfo.authType = authType;
    coAuthInfo.callerID = callerID;
    coAuthInfo.contextID = contextID;
    coAuthInfo.pkgName = callerName;
    coAuthInfo.userID = userID;
    result = userauthController_.coAuth(coAuthInfo, callback);
    if (result != SUCCESS) {
        USERAUTH_HILOGE(MODULE_SERVICE, "UserAuthService Auth coAuth is ERROR!");
        callback->onResult(result, extraInfo);
        return ret;
    }
    return contextID;
}

uint64_t UserAuthService::AuthUser(const int32_t userId, const uint64_t challenge,
                                   const AuthType authType, const AuthTurstLevel authTurstLevel,
                                   sptr<IUserAuthCallback>& callback)
{
    USERAUTH_HILOGD(MODULE_SERVICE, "UserAuthService AuthUser is start");
    int ret = SUCCESS;
    int result = SUCCESS;
    uint64_t callerID = 0;
    std::string callerName = "";
    uint64_t contextID = 0;
    AuthSolution authSolutionParam;
    CoAuthInfo coAuthInfo;
    AuthResult extraInfo;

    sptr<IRemoteObject::DeathRecipient> dr = new UserAuthServiceCallbackDeathRecipient(callback);
    if ((!callback->AsObject()->AddDeathRecipient(dr))) {
        USERAUTH_HILOGE(MODULE_SERVICE, "Failed to add death recipient UserAuthServiceCallbackDeathRecipient");
    }

    if (GetControllerData(callback, extraInfo, authTurstLevel, callerID, callerName, contextID) == FAIL) {
        return ret;
    }

    authSolutionParam.contextId = contextID;
    authSolutionParam.userId = userId;
    authSolutionParam.authTrustLevel = authTurstLevel;
    authSolutionParam.challenge = challenge;
    authSolutionParam.authType = authType;
    result = userauthController_.GenerateSolution(authSolutionParam, coAuthInfo.sessionIds);
    if (result != SUCCESS) {
        USERAUTH_HILOGE(MODULE_SERVICE, "UserAuthService AuthUser GenerateSolution is ERROR!");
        userauthController_.DeleteContextID(contextID);
        callback->onResult(result, extraInfo);
        return ret;
    }

    coAuthInfo.authType = authType;
    coAuthInfo.callerID = callerID;
    coAuthInfo.contextID = contextID;
    coAuthInfo.pkgName = callerName;
    coAuthInfo.userID = userId;
    result = userauthController_.coAuth(coAuthInfo, callback);
    if (result != SUCCESS) {
        USERAUTH_HILOGE(MODULE_SERVICE, "UserAuthService AuthUser coAuth is ERROR!");
        userauthController_.DeleteContextID(contextID);
        callback->onResult(result, extraInfo);
        return ret;
    }
    return contextID;
}

int32_t UserAuthService::GetControllerData(sptr<IUserAuthCallback>& callback, AuthResult &extraInfo,
                                           const AuthTurstLevel authTurstLevel, uint64_t &callerID,
                                           std::string &callerName, uint64_t &contextID)
{
    int ret = SUCCESS;
    int result = SUCCESS;
    if (callback == nullptr) {
        USERAUTH_HILOGE(MODULE_SERVICE, "UserAuthService AuthUser IUserAuthCallback is NULL!");
        ret = FAIL;
        return ret;
    }
    if (ATL4 < authTurstLevel || authTurstLevel < ATL1) {
        USERAUTH_HILOGE(MODULE_SERVICE, "UserAuthService AuthUser AuthTurstLevel is NOT SUPPORT!");
        callback->onResult(TRUST_LEVEL_NOT_SUPPORT, extraInfo);
        ret = FAIL;
        return ret;
    }

    callerID = this->GetCallingUid();
    callerName = std::to_string(callerID);

    result = userauthController_.GenerateContextID(contextID);
    if (result != SUCCESS) {
        USERAUTH_HILOGE(MODULE_SERVICE, "UserAuthService AuthUser GenerateContextID is ERROR!");
        callback->onResult(GENERAL_ERROR, extraInfo);
        ret = FAIL;
        return ret;
    }
    result = userauthController_.AddContextID(contextID);
    if (result != SUCCESS) {
        USERAUTH_HILOGE(MODULE_SERVICE, "UserAuthService AuthUser AddContextID is ERROR!");
        callback->onResult(GENERAL_ERROR, extraInfo);
        ret = FAIL;
        return ret;
    }
    return ret;
}

int32_t UserAuthService::CancelAuth(const uint64_t contextId)
{
    USERAUTH_HILOGD(MODULE_SERVICE, "UserAuthService CancelAuth is start");
    int result = INVALID_CONTEXTID;
    std::vector<uint64_t>  sessionIds;

    int ret = userauthController_.IsContextIDExist(contextId);
    if (ret != SUCCESS) {
        USERAUTH_HILOGE(MODULE_SERVICE, "UserAuthService CancelAuth IsContextIDExist is ERROR!");
        return result;
    }

    result = userauthController_.CancelContext(contextId, sessionIds);
    if (result == SUCCESS) {
        for (auto const &item : sessionIds) {
            result = userauthController_.Cancel(item);
            if (result != SUCCESS) {
                USERAUTH_HILOGE(MODULE_SERVICE, "UserAuthService CancelAuth Cancel is ERROR!");
            }
        }
        userauthController_.DeleteContextID(contextId);
    }

    return result;
}

int32_t UserAuthService::GetVersion()
{
    USERAUTH_HILOGD(MODULE_SERVICE, "UserAuthService GetVersion is start");
    return userauthController_.GetVersion();
}
UserAuthService::UserAuthServiceCallbackDeathRecipient::UserAuthServiceCallbackDeathRecipient(
    sptr<IUserAuthCallback>& impl)
{
    if (impl != nullptr) {
        callback_ = impl;
    } else {
        USERAUTH_HILOGE(MODULE_SERVICE, "UserAuthServiceCallbackDeathRecipient is error");
    }
}
void UserAuthService::UserAuthServiceCallbackDeathRecipient::OnRemoteDied(const wptr<IRemoteObject>& remote)
{
    if (remote == nullptr) {
        USERAUTH_HILOGE(MODULE_SERVICE,
            "UserAuthServiceCallbackDeathRecipient OnRemoteDied failed, remote is nullptr");
        return;
    }
    callback_ = nullptr;

    USERAUTH_HILOGE(MODULE_SERVICE, "UserAuthServiceCallbackDeathRecipient::Recv death notice.");
}
} // namespace UserAuth
} // namespace UserIam
} // namespace OHOS
