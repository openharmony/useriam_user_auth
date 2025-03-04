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

#include "useridm_controller.h"
#include "useridm_callback_proxy.h"
#include "useridm_hilog_wrapper.h"
#include "useridm_adapter.h"

namespace OHOS {
namespace UserIAM {
namespace UserIDM {
UserIDMController::UserIDMController()
{
    USERIDM_HILOGD(MODULE_SERVICE, "UserIDMController constructor");
    data_ = std::make_shared<UserIDMModule>();
}

UserIDMController::~UserIDMController()
{
    USERIDM_HILOGD(MODULE_SERVICE, "UserIDMController deconstructor");
}

void UserIDMController::OpenEditSessionCtrl(int32_t userId, uint64_t &challenge)
{
    USERIDM_HILOGD(MODULE_SERVICE, "OpenEditSessionCtrl start");

    uint64_t sessionId = 0;
    uint64_t temp = 0;
    bool res = data_->CheckScheduleIdIsActive(sessionId);
    if (res && (data_->CheckChallenge(temp))) {
        CoAuth::CoAuthManager::GetInstance().Cancel(sessionId);
    }
    data_->CleanData();

    UserIDMAdapter::GetInstance().OpenEditSession(userId, challenge);
    data_->InsertChallenge(challenge);
}

void UserIDMController::CloseEditSessionCtrl()
{
    USERIDM_HILOGD(MODULE_SERVICE, "CloseEditSessionCtrl start");

    uint64_t sessionId = 0;
    uint64_t temp = 0;
    bool res = data_->CheckScheduleIdIsActive(sessionId);
    if (res && (data_->CheckChallenge(temp))) {
        CoAuth::CoAuthManager::GetInstance().Cancel(sessionId);
    }
    data_->CleanData();

    UserIDMAdapter::GetInstance().CloseEditSession();
}

void UserIDMController::CloseEditSessionCtrl(int32_t userId)
{
    USERIDM_HILOGD(MODULE_SERVICE, "CloseEditSessionCtrl start");

    int result = UserIDMAdapter::GetInstance().CloseEditSession(userId);
    if (result != SUCCESS) {
        USERIDM_HILOGD(MODULE_SERVICE, "CloseEditSessionCtrl fail");
        return;
    }
    uint64_t sessionId = 0;
    uint64_t temp = 0;
    bool res = data_->CheckScheduleIdIsActive(sessionId);
    if (res && (data_->CheckChallenge(temp))) {
        CoAuth::CoAuthManager::GetInstance().Cancel(sessionId);
    }
    data_->CleanData();
}

int32_t UserIDMController::GetAuthInfoCtrl(int32_t userId, AuthType authType, std::vector<CredentialInfo>& credInfos)
{
    USERIDM_HILOGD(MODULE_SERVICE, "GetAuthInfoCtrl start");
    return UserIDMAdapter::GetInstance().QueryCredential(userId, authType, credInfos);
}

int32_t UserIDMController::GetSecureInfoCtrl(int32_t userId, uint64_t& secureUid,
    std::vector<EnrolledInfo>& enrolledInfos)
{
    USERIDM_HILOGD(MODULE_SERVICE, "GetSecureInfoCtrl start");
    return UserIDMAdapter::GetInstance().GetSecureUid(userId, secureUid, enrolledInfos);
}

int32_t UserIDMController::DeleteCredentialCtrl(int32_t userId, uint64_t credentialId,
    const std::vector<uint8_t>& authToken, CredentialInfo& credInfo)
{
    USERIDM_HILOGD(MODULE_SERVICE, "DeleteCredentialCtrl start");
    return UserIDMAdapter::GetInstance().DeleteCredential(userId, credentialId, authToken, credInfo);
}

int32_t UserIDMController::DeleteUserCtrl(int32_t userId, const std::vector<uint8_t>& authToken,
    std::vector<CredentialInfo>& credInfo)
{
    USERIDM_HILOGD(MODULE_SERVICE, "DeleteUserCtrl start");
    return UserIDMAdapter::GetInstance().DeleteUser(userId, authToken, credInfo);
}

int32_t UserIDMController::DeleteUserByForceCtrl(int32_t userId, std::vector<CredentialInfo>& credInfo)
{
    USERIDM_HILOGD(MODULE_SERVICE, "DeleteUserByForceCtrl start");
    return UserIDMAdapter::GetInstance().DeleteUserEnforce(userId, credInfo);
}

int32_t UserIDMController::AddCredentialCallCoauth(uint64_t callerID, const AddCredInfo& credInfo,
    const sptr<IIDMCallback>& innerkitsCallback, uint64_t& challenge, CoAuth::ScheduleInfo& info)
{
    USERIDM_HILOGD(MODULE_SERVICE, "AddCredentialCallCoauth start");
    if (innerkitsCallback == nullptr) {
        USERIDM_HILOGE(MODULE_SERVICE, "sorry: innerkitsCallback is nullptr");
        return INVALID_PARAMETERS;
    }

    std::string callerName = std::to_string(callerID);
    data_->InsertScheduleId(info.scheduleId);
    CoAuth::AuthInfo paramInfo;
    paramInfo.SetPkgName(callerName);
    paramInfo.SetCallerUid(callerID);
    std::shared_ptr<UserIDMCoAuthHandler> coAuthCallback;

    USERIDM_HILOGI(MODULE_SERVICE, "credInfo.authType is %{public}d", credInfo.authType);
    if (credInfo.authType == PIN) {
        coAuthCallback = std::make_shared<UserIDMCoAuthHandler>(ADD_PIN_CRED, challenge, info.scheduleId, data_,
            innerkitsCallback);
    } else if (FACE == credInfo.authType) {
        coAuthCallback = std::make_shared<UserIDMCoAuthHandler>(ADD_FACE_CRED, challenge, info.scheduleId, data_,
            innerkitsCallback);
    } else {
        USERIDM_HILOGE(MODULE_SERVICE, "credInfo.authType error: %{public}d", credInfo.authType);
        coAuthCallback = std::make_shared<UserIDMCoAuthHandler>(ADD_PIN_CRED, challenge, info.scheduleId, data_,
            innerkitsCallback);
    }

    if (coAuthCallback == nullptr) {
        USERIDM_HILOGE(MODULE_SERVICE, "sorry: coAuthCallback is nullptr");
        return FAIL;
    } else {
        CoAuth::CoAuthManager::GetInstance().BeginSchedule(info, paramInfo, coAuthCallback);
    }
    return SUCCESS;
}

int32_t UserIDMController::AddCredentialCtrl(int32_t userId, uint64_t callerID, const AddCredInfo& credInfo,
    const sptr<IIDMCallback>& innerkitsCallback)
{
    USERIDM_HILOGD(MODULE_SERVICE, "AddCredentialCtrl start");

    if (innerkitsCallback == nullptr) {
        USERIDM_HILOGE(MODULE_SERVICE, "sorry: innerkitsCallback is nullptr");
        return INVALID_PARAMETERS;
    }
    uint64_t challenge = 0;

    bool result = data_->CheckChallenge(challenge);
    if (!result) {
        USERIDM_HILOGE(MODULE_SERVICE, "check challenge num error: no challenge");
        RequestResult reqRet;
        innerkitsCallback->OnResult(FAIL, reqRet);
        return FAIL;
    }
    uint64_t scheduleId = 0;
    result = data_->CheckScheduleIdIsActive(scheduleId);
    if (result) {
        USERIDM_HILOGE(MODULE_SERVICE, "current session in active: busy");
        RequestResult reqRet;
        innerkitsCallback->OnResult(BUSY, reqRet);
        return BUSY;
    }
    CoAuth::ScheduleInfo info = {};
    int32_t ret = UserIDMAdapter::GetInstance().InitSchedule(credInfo.token, userId, credInfo.authType,
        credInfo.authSubType, info);
    if (ret == SUCCESS) {
        ret = AddCredentialCallCoauth(callerID, credInfo, innerkitsCallback, challenge, info);
    } else {
        USERIDM_HILOGE(MODULE_SERVICE, "call driver info: InitSchedule failed");
        RequestResult reqRet;
        innerkitsCallback->OnResult(FAIL, reqRet);
    }
    return ret;
}

int32_t UserIDMController::UpdateCredentialCtrl(int32_t userId, uint64_t callerID, std::string callerName,
    const AddCredInfo& credInfo, const sptr<IIDMCallback>& innerkitsCallback)
{
    USERIDM_HILOGD(MODULE_SERVICE, "UpdateCredentialCtrl start");
    if (innerkitsCallback == nullptr) {
        USERIDM_HILOGE(MODULE_SERVICE, "sorry: innerkitsCallback is nullptr");
        return INVALID_PARAMETERS;
    }

    uint64_t scheduleId = 0;
    uint64_t challenge = 0;
    bool result = data_->CheckChallenge(challenge);
    if (!result) {
        USERIDM_HILOGE(MODULE_SERVICE, "check challenge num error: no challenge");
        RequestResult reqRet;
        innerkitsCallback->OnResult(FAIL, reqRet);
        return FAIL;
    }
    result = data_->CheckScheduleIdIsActive(scheduleId);
    if (result) {
        USERIDM_HILOGE(MODULE_SERVICE, "current session in active: busy");
        RequestResult reqRet;
        innerkitsCallback->OnResult(BUSY, reqRet);
        return BUSY;
    }
    CoAuth::ScheduleInfo info;
    int32_t ret = UserIDMAdapter::GetInstance().InitSchedule(credInfo.token, userId, credInfo.authType,
        credInfo.authSubType, info);
    if (ret == SUCCESS) {
        USERIDM_HILOGI(MODULE_SERVICE, "InitSchedule SUCCESS");
        data_->InsertScheduleId(info.scheduleId);
        std::shared_ptr<UserIDMCoAuthHandler> coAuthCallback =
            std::make_shared<UserIDMCoAuthHandler>(MODIFY_CRED, challenge, info.scheduleId, data_, innerkitsCallback);
        CoAuth::AuthInfo paramInfo;
        paramInfo.SetPkgName(callerName);
        paramInfo.SetCallerUid(callerID);
        CoAuth::CoAuthManager::GetInstance().BeginSchedule(info, paramInfo, coAuthCallback);
    } else {
        USERIDM_HILOGE(MODULE_SERVICE, "call driver info: InitSchedule failed");
        RequestResult reqRet;
        innerkitsCallback->OnResult(FAIL, reqRet);
    }
    return ret;
}

int32_t UserIDMController::DelSchedleIdCtrl(uint64_t challenge)
{
    USERIDM_HILOGD(MODULE_SERVICE, "DelSchedleIdCtrl start");
    int32_t result = FAIL;
    uint64_t sessionId = 0;
    uint64_t lastChallenge = 0;
    data_->CheckChallenge(lastChallenge);
    if (lastChallenge != challenge) {
        USERIDM_HILOGE(MODULE_SERVICE, "Not same challenge num");
        return result;
    }
    if (!data_->CheckScheduleIdIsActive(sessionId)) {
        USERIDM_HILOGE(MODULE_SERVICE, "CheckScheduleIdIsActive fail");
        return result;
    }
    result = CoAuth::CoAuthManager::GetInstance().Cancel(sessionId);
    if (result != SUCCESS) {
        USERIDM_HILOGE(MODULE_SERVICE, "Cancel fail");
        return result;
    }
    data_->DeleteSessionId();
    return result;
}

int32_t UserIDMController::DelSchedleIdCtrl(int32_t userId)
{
    USERIDM_HILOGD(MODULE_SERVICE, "DelSchedleIdCtrl start");
    int32_t result = UserIDMAdapter::GetInstance().Cancel(userId);
    if (result != SUCCESS) {
        USERIDM_HILOGE(MODULE_SERVICE, "Cancel fail");
        return result;
    }
    uint64_t sessionId = 0;
    uint64_t lastChallenge = 0;
    if (!data_->CheckChallenge(lastChallenge)) {
        USERIDM_HILOGE(MODULE_SERVICE, "CheckChallenge fail");
        return result;
    }
    if (!data_->CheckScheduleIdIsActive(sessionId)) {
        USERIDM_HILOGE(MODULE_SERVICE, "CheckScheduleIdIsActive fail");
        return result;
    }
    int32_t coAuthRet = CoAuth::CoAuthManager::GetInstance().Cancel(sessionId);
    if (coAuthRet != SUCCESS) {
        USERIDM_HILOGE(MODULE_SERVICE, "CoAuth cancel fail");
    }
    data_->DeleteSessionId();
    return result;
}

int32_t UserIDMController::DelFaceCredentialCtrl(AuthType authType, AuthSubType authSubType, uint64_t credentialId,
    uint64_t templateId, const sptr<IIDMCallback>& innerCallback)
{
    USERIDM_HILOGD(MODULE_SERVICE, "DelFaceCredentialCtrl start authType: %{public}d", authType);
    if (authType != FACE) {
        USERIDM_HILOGE(MODULE_SERVICE, "authType error");
        return FAIL;
    }
    std::shared_ptr<UserIDMSetPropHandler> setPropCallback =
        std::make_shared<UserIDMSetPropHandler>(FACE, 0, 0, credentialId, data_, innerCallback);
    AuthResPool::AuthAttributes condition;
    condition.SetUint32Value(AuthAttributeType::AUTH_PROPERTY_MODE, 0);
    condition.SetUint64Value(AuthAttributeType::AUTH_CALLER_UID, 0);
    condition.SetUint32Value(AuthAttributeType::AUTH_TYPE, authType);
    condition.SetUint64Value(AuthAttributeType::AUTH_SUBTYPE, authSubType);
    condition.SetUint64Value(AuthAttributeType::AUTH_CREDENTIAL_ID, credentialId);
    condition.SetUint64Value(AuthAttributeType::AUTH_TEMPLATE_ID, templateId);
    CoAuth::CoAuthManager::GetInstance().SetExecutorProp(condition, setPropCallback);
    return SUCCESS;
}

int32_t UserIDMController::DelExecutorPinInfoCtrl(const sptr<IIDMCallback>& innerCallback,
    std::vector<CredentialInfo>& info)
{
    USERIDM_HILOGD(MODULE_SERVICE, "DelExecutorPinInfoCtrl start: info.size(): %{public}zu", info.size());

    const size_t minDelSize = 1;
    if (info.size() < minDelSize) {
        USERIDM_HILOGE(MODULE_SERVICE, "info size error!: %{public}zu", info.size());
        RequestResult reqRet;
        innerCallback->OnResult(FAIL, reqRet);
        return FAIL;
    }

    for (uint32_t i = 0; i < info.size(); i++) {
        if (info[i].authType == PIN) {
            std::shared_ptr<UserIDMSetPropHandler> setPropCallback =
                std::make_shared<UserIDMSetPropHandler>(PIN, 0, 0, info[i].credentialId, data_, innerCallback);
            AuthResPool::AuthAttributes condition;
            condition.SetUint32Value(AuthAttributeType::AUTH_PROPERTY_MODE, 0);
            condition.SetUint64Value(AuthAttributeType::AUTH_CALLER_UID, 0);
            condition.SetUint32Value(AuthAttributeType::AUTH_TYPE, info[i].authType);
            condition.SetUint64Value(AuthAttributeType::AUTH_SUBTYPE, info[i].authSubType);
            condition.SetUint64Value(AuthAttributeType::AUTH_CREDENTIAL_ID, info[i].credentialId);
            condition.SetUint64Value(AuthAttributeType::AUTH_TEMPLATE_ID, info[i].templateId);
            CoAuth::CoAuthManager::GetInstance().SetExecutorProp(condition, setPropCallback);
        } else if (info[i].authType == FACE) {
            std::shared_ptr<UserIDMSetPropHandler> setPropCallback =
                std::make_shared<UserIDMSetPropHandler>(FACE, 0, 0, info[i].credentialId, data_, innerCallback);
            AuthResPool::AuthAttributes condition;
            condition.SetUint32Value(AuthAttributeType::AUTH_PROPERTY_MODE, 0);
            condition.SetUint64Value(AuthAttributeType::AUTH_CALLER_UID, 0);
            condition.SetUint32Value(AuthAttributeType::AUTH_TYPE, info[i].authType);
            condition.SetUint64Value(AuthAttributeType::AUTH_SUBTYPE, info[i].authSubType);
            condition.SetUint64Value(AuthAttributeType::AUTH_CREDENTIAL_ID, info[i].credentialId);
            condition.SetUint64Value(AuthAttributeType::AUTH_TEMPLATE_ID, info[i].templateId);
            CoAuth::CoAuthManager::GetInstance().SetExecutorProp(condition, setPropCallback);
        }
    }
    return SUCCESS;
}
}  // namespace UserIDM
}  // namespace UserIAM
}  // namespace OHOS
