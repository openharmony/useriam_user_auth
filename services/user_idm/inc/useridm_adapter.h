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

#ifndef USERAUTH_ADAPTER_H
#define USERAUTH_ADAPTER_H

#include "v1_0/user_auth_interface_proxy.h"
#include "coauth_manager.h"
#include "useridm_info.h"

namespace OHOS {
namespace UserIAM {
namespace UserIDM {
class UserIDMAdapter {
public:
    static UserIDMAdapter &GetInstance();
    void OpenEditSession(int32_t userId, uint64_t& challenge);
    void CloseEditSession();
    int32_t CloseEditSession(int32_t userId);
    int32_t QueryCredential(int32_t userId, AuthType authType, std::vector<CredentialInfo>& credInfos);
    int32_t GetSecureUid(int32_t userId, uint64_t& secureUid, std::vector<EnrolledInfo>& enrolledInfos);
    int32_t InitSchedule(std::vector<uint8_t> autoToken, int32_t userId, AuthType authType,
        AuthSubType authSubType, CoAuth::ScheduleInfo& info);
    int32_t Cancel(int32_t userId);
    int32_t DeleteCredential(int32_t userId, uint64_t credentialId, const std::vector<uint8_t>& authToken,
        CredentialInfo& credInfo);
    int32_t DeleteUser(int32_t userId, const std::vector<uint8_t>& authToken, std::vector<CredentialInfo>& credInfo);
    int32_t DeleteUserEnforce(int32_t userId, std::vector<CredentialInfo>& credInfo);
    int32_t AddCredential(std::vector<uint8_t>& enrollToken, uint64_t& credentialId);
    int32_t UpdateCredential(std::vector<uint8_t> enrollToken, uint64_t &credentialId,
        CredentialInfo &deletedCredential);

private:
    UserIDMAdapter() = default;
    ~UserIDMAdapter() = default;
    bool CopyScheduleInfo(const HDI::UserAuth::V1_0::ScheduleInfo& in, CoAuth::ScheduleInfo& out);
    void CopyCredentialFromHdi(const HDI::UserAuth::V1_0::CredentialInfo& in, UserIDM::CredentialInfo& out);
};
} // namespace UserIDM
} // namespace UserIam
} // namespace OHOS
#endif // USERAUTH_ADAPTER_H
