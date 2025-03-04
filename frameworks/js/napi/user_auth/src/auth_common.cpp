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

#include "auth_common.h"
#include "userauth_hilog_wrapper.h"

namespace OHOS {
namespace UserIAM {
namespace UserAuth {
ExecuteInfo::ExecuteInfo(napi_env napiEnv) : env(napiEnv)
{
}

ExecuteInfo::~ExecuteInfo()
{
    if (env != nullptr && callbackRef != nullptr) {
        USERAUTH_HILOGI(MODULE_JS_NAPI, "ExecuteInfo::~ExecuteInfo delete callbackRef");
        napi_delete_reference(env, callbackRef);
        callbackRef = nullptr;
    }
}

AuthInfo::AuthInfo(napi_env napiEnv) : env(napiEnv)
{
}

AuthInfo::~AuthInfo()
{
    if (env == nullptr) {
        return;
    }
    if (onResult != nullptr) {
        USERAUTH_HILOGI(MODULE_JS_NAPI, "AuthInfo::~AuthInfo delete onResult");
        napi_delete_reference(env, onResult);
        onResult = nullptr;
    }
    if (onAcquireInfo != nullptr) {
        USERAUTH_HILOGI(MODULE_JS_NAPI, "AuthInfo::~AuthInfo delete onAcquireInfo");
        napi_delete_reference(env, onAcquireInfo);
        onAcquireInfo = nullptr;
    }
}

AuthUserInfo::AuthUserInfo(napi_env napiEnv) : env(napiEnv)
{
}

AuthUserInfo::~AuthUserInfo()
{
    if (env == nullptr) {
        return;
    }
    if (onResult != nullptr) {
        USERAUTH_HILOGI(MODULE_JS_NAPI, "AuthUserInfo::~AuthUserInfo delete onResult");
        napi_delete_reference(env, onResult);
        onResult = nullptr;
    }
    if (onAcquireInfo != nullptr) {
        USERAUTH_HILOGI(MODULE_JS_NAPI, "AuthUserInfo::~AuthUserInfo delete onAcquireInfo");
        napi_delete_reference(env, onAcquireInfo);
        onAcquireInfo = nullptr;
    }
}
} // namespace UserAuth
} // namespace UserIAM
} // namespace OHOS