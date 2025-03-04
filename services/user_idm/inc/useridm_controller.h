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

#ifndef USERIDM_CONTROLLER_H
#define USERIDM_CONTROLLER_H

#include "useridm_info.h"
#include "useridm_coauth_handler.h"
#include "auth_info.h"
#include "auth_attributes.h"
#include "coauth_manager.h"

namespace OHOS {
namespace UserIAM {
namespace UserIDM {
const int64_t delay_time = 30 * 1000;
class UserIDMController : public Singleton<UserIDMController> {
public:
    UserIDMController();
    ~UserIDMController();
    void OpenEditSessionCtrl(int32_t userId, uint64_t& challenge);
    void CloseEditSessionCtrl();
    void CloseEditSessionCtrl(int32_t userId);
    int32_t GetAuthInfoCtrl(int32_t userId, AuthType authType, std::vector<CredentialInfo>& credInfos);
    int32_t GetSecureInfoCtrl(int32_t userId, uint64_t& secureUid, std::vector<EnrolledInfo>& enrolledInfos);
    int32_t DeleteCredentialCtrl(int32_t userId, uint64_t credentialId,
        const std::vector<uint8_t>& authToken, CredentialInfo& credInfo);
    int32_t DeleteUserCtrl(int32_t userId, const std::vector<uint8_t>& authToken,
        std::vector<CredentialInfo>& credInfo);
    int32_t DeleteUserByForceCtrl(int32_t userId, std::vector<CredentialInfo>& credInfo);
    int32_t AddCredentialCtrl(int32_t userId, uint64_t callerID, const AddCredInfo& credInfo,
        const sptr<IIDMCallback>& innerkitsCallback);
    int32_t AddCredentialCallCoauth(uint64_t callerID, const AddCredInfo& credInfo,
        const sptr<IIDMCallback>& innerkitsCallback, uint64_t& challenge, CoAuth::ScheduleInfo& info);
    int32_t UpdateCredentialCtrl(int32_t userId, uint64_t callerID, std::string callerName,
        const AddCredInfo& credInfo, const sptr<IIDMCallback>& innerCallback);
    int32_t DelSchedleIdCtrl(uint64_t challenge);
    int32_t DelSchedleIdCtrl(int32_t userId);
    int32_t DelFaceCredentialCtrl(AuthType authType, AuthSubType authSubType,
        uint64_t credentialId, uint64_t templateId, const sptr<IIDMCallback>& innerCallback);
    int32_t DelExecutorPinInfoCtrl(const sptr<IIDMCallback>& innerCallback, std::vector<CredentialInfo>& info);

private:
    std::shared_ptr<UserIDMModule> data_;
};
}  // namespace UserIDM
}  // namespace UserIAM
}  // namespace OHOS

#endif // USERIDM_CONTROLLER_H
