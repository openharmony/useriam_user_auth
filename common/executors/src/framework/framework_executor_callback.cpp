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

#include "framework_executor_callback.h"

#include <mutex>
#include <sstream>

#include "auth_command.h"
#include "custom_command.h"
#include "enroll_command.h"
#include "iam_check.h"
#include "iam_logger.h"
#include "iam_mem.h"
#include "iam_ptr.h"
#include "identify_command.h"

#define LOG_LABEL Common::LABEL_USER_AUTH_EXECUTOR

namespace OHOS {
namespace UserIAM {
namespace UserAuth {
FrameworkExecutorCallback::FrameworkExecutorCallback(std::weak_ptr<Executor> executor) : executor_(executor)
{
    uint32_t callbackId = GenerateExecutorCallbackId();
    std::ostringstream ss;
    ss << "ExecutorCallback(Id:" << callbackId << ")";
    description_ = ss.str();
}

int32_t FrameworkExecutorCallback::OnBeginExecute(
    uint64_t scheduleId, std::vector<uint8_t> &publicKey, std::shared_ptr<AuthAttributes> commandAttrs)
{
    return OnBeginExecuteInner(scheduleId, publicKey, commandAttrs);
}

ResultCode FrameworkExecutorCallback::OnBeginExecuteInner(
    uint64_t scheduleId, std::vector<uint8_t> &publicKey, std::shared_ptr<AuthAttributes> commandAttrs)
{
    static_cast<void>(publicKey);
    IF_FALSE_LOGE_AND_RETURN_VAL(commandAttrs != nullptr, ResultCode::GENERAL_ERROR);
    uint32_t commandId = 0;
    IF_FALSE_LOGE_AND_RETURN_VAL(
        commandAttrs->GetUint32Value(AUTH_SCHEDULE_MODE, commandId) == USERAUTH_SUCCESS, ResultCode::GENERAL_ERROR);

    IAM_LOGI("%{public}s start process cmd %{public}u", GetDescription(), commandId);
    ResultCode ret = ResultCode::GENERAL_ERROR;
    switch (commandId) {
        case SCHEDULE_MODE_ENROLL:
            ret = ProcessEnrollCommand(scheduleId, commandAttrs);
            break;
        case SCHEDULE_MODE_AUTH:
            ret = ProcessAuthCommand(scheduleId, commandAttrs);
            break;
        default:
            IAM_LOGE("command id %{public}u is not supported", commandId);
    }

    IAM_LOGI("command id = %{public}u ret = %{public}d", commandId, ret);
    return ret;
}

int32_t FrameworkExecutorCallback::OnEndExecute(uint64_t scheduleId, std::shared_ptr<AuthAttributes> consumerAttr)
{
    return OnEndExecuteInner(scheduleId, consumerAttr);
}

ResultCode FrameworkExecutorCallback::OnEndExecuteInner(
    uint64_t scheduleId, std::shared_ptr<AuthAttributes> consumerAttr)
{
    IF_FALSE_LOGE_AND_RETURN_VAL(consumerAttr != nullptr, ResultCode::GENERAL_ERROR);
    uint32_t commandId = 0;
    IF_FALSE_LOGE_AND_RETURN_VAL(
        consumerAttr->GetUint32Value(AUTH_SCHEDULE_MODE, commandId) == USERAUTH_SUCCESS, ResultCode::GENERAL_ERROR);

    IAM_LOGI("%{public}s start process cmd %{public}u", GetDescription(), commandId);
    ResultCode ret = ResultCode::GENERAL_ERROR;
    switch (commandId) {
        case SCHEDULE_MODE_AUTH:
            ret = ProcessCancelCommand(scheduleId);
            break;
        case SCHEDULE_MODE_ENROLL:
            ret = ProcessCancelCommand(scheduleId);
            break;
        default:
            IAM_LOGE("Command id %{public}u is not supported", commandId);
            break;
    }
    IAM_LOGI("command id = %{public}u ret = %{public}d", commandId, ret);
    return ret;
}

void FrameworkExecutorCallback::OnMessengerReady(
    const sptr<IExecutorMessenger> &messenger, std::vector<uint8_t> &publicKey, std::vector<uint64_t> &templateIds)
{
    IAM_LOGI("%{public}s start", GetDescription());
    auto executor = executor_.lock();
    if (executor == nullptr) {
        IAM_LOGE("executor has been released, process failed");
        return;
    }
    auto hdi = executor->GetExecutorHdi();
    IF_FALSE_LOGE_AND_RETURN(hdi != nullptr);
    executorMessenger_ = messenger;
    std::vector<uint8_t> extraInfo;
    hdi->OnRegisterFinish(templateIds, publicKey, extraInfo);
}

int32_t FrameworkExecutorCallback::OnSetProperty(std::shared_ptr<AuthAttributes> properties)
{
    return OnSetPropertyInner(properties);
}

ResultCode FrameworkExecutorCallback::OnSetPropertyInner(std::shared_ptr<AuthAttributes> properties)
{
    IF_FALSE_LOGE_AND_RETURN_VAL(properties != nullptr, ResultCode::GENERAL_ERROR);
    uint32_t commandId = 0;
    IF_FALSE_LOGE_AND_RETURN_VAL(
        properties->GetUint32Value(AUTH_PROPERTY_MODE, commandId) == USERAUTH_SUCCESS, ResultCode::GENERAL_ERROR);
    IAM_LOGI("%{public}s start process cmd %{public}u", GetDescription(), commandId);
    ResultCode ret = ResultCode::GENERAL_ERROR;
    if (commandId == PROPERMODE_DELETE) {
        ret = ProcessDeleteTemplateCommand(properties);
    } else {
        ret = ProcessCustomCommand(properties);
    }
    IAM_LOGI("command id = %{public}u ret = %{public}d", commandId, ret);
    return ret;
}

int32_t FrameworkExecutorCallback::OnGetProperty(
    std::shared_ptr<AuthAttributes> conditions, std::shared_ptr<AuthAttributes> values)
{
    return OnGetPropertyInner(conditions, values);
}

ResultCode FrameworkExecutorCallback::OnGetPropertyInner(
    std::shared_ptr<AuthAttributes> conditions, std::shared_ptr<AuthAttributes> values)
{
    IAM_LOGI("%{public}s start", GetDescription());
    IF_FALSE_LOGE_AND_RETURN_VAL(conditions != nullptr, ResultCode::GENERAL_ERROR);
    uint32_t commandId = 0;
    IF_FALSE_LOGE_AND_RETURN_VAL(
        conditions->GetUint32Value(AUTH_PROPERTY_MODE, commandId) == USERAUTH_SUCCESS, ResultCode::GENERAL_ERROR);
    if (commandId != PROPERMODE_GET) {
        IAM_LOGE("command id not recognised");
        return ResultCode::GENERAL_ERROR;
    }
    ResultCode ret = ProcessGetTemplateCommand(conditions, values);
    IAM_LOGI("command id = %{public}u ret = %{public}d", commandId, ret);
    return ret;
}

ResultCode FrameworkExecutorCallback::ProcessEnrollCommand(
    uint64_t scheduleId, std::shared_ptr<AuthAttributes> properties)
{
    auto command = Common::MakeShared<EnrollCommand>(executor_, scheduleId, properties, executorMessenger_);
    IF_FALSE_LOGE_AND_RETURN_VAL(command != nullptr, ResultCode::GENERAL_ERROR);
    return command->StartProcess();
}

ResultCode FrameworkExecutorCallback::ProcessAuthCommand(
    uint64_t scheduleId, std::shared_ptr<AuthAttributes> properties)
{
    auto command = Common::MakeShared<AuthCommand>(executor_, scheduleId, properties, executorMessenger_);
    IF_FALSE_LOGE_AND_RETURN_VAL(command != nullptr, ResultCode::GENERAL_ERROR);
    return command->StartProcess();
}

ResultCode FrameworkExecutorCallback::ProcessIdentifyCommand(
    uint64_t scheduleId, std::shared_ptr<AuthAttributes> properties)
{
    auto command = Common::MakeShared<IdentifyCommand>(executor_, scheduleId, properties, executorMessenger_);
    IF_FALSE_LOGE_AND_RETURN_VAL(command != nullptr, ResultCode::GENERAL_ERROR);
    return command->StartProcess();
}

ResultCode FrameworkExecutorCallback::ProcessCancelCommand(uint64_t scheduleId)
{
    auto executor = executor_.lock();
    if (executor == nullptr) {
        IAM_LOGE("executor has been released, process failed");
        return ResultCode::GENERAL_ERROR;
    }
    auto hdi = executor->GetExecutorHdi();
    IF_FALSE_LOGE_AND_RETURN_VAL(hdi != nullptr, ResultCode::GENERAL_ERROR);
    hdi->Cancel(scheduleId);
    return ResultCode::SUCCESS;
}

ResultCode FrameworkExecutorCallback::ProcessDeleteTemplateCommand(std::shared_ptr<AuthAttributes> properties)
{
    IAM_LOGI("start");
    IF_FALSE_LOGE_AND_RETURN_VAL(properties != nullptr, ResultCode::GENERAL_ERROR);
    auto executor = executor_.lock();
    if (executor == nullptr) {
        IAM_LOGE("executor has been released, process failed");
        return ResultCode::GENERAL_ERROR;
    }
    auto hdi = executor->GetExecutorHdi();
    IF_FALSE_LOGE_AND_RETURN_VAL(hdi != nullptr, ResultCode::GENERAL_ERROR);
    uint64_t templateId = 0;
    properties->GetUint64Value(AUTH_TEMPLATE_ID, templateId);
    std::vector<uint64_t> templateIdList;
    templateIdList.push_back(templateId);
    hdi->Delete(templateIdList);
    return ResultCode::SUCCESS;
}

ResultCode FrameworkExecutorCallback::ProcessCustomCommand(std::shared_ptr<AuthAttributes> properties)
{
    auto command = Common::MakeShared<CustomCommand>(executor_, properties);
    IF_FALSE_LOGE_AND_RETURN_VAL(command != nullptr, ResultCode::GENERAL_ERROR);
    ResultCode ret = command->StartProcess();
    if (ret != ResultCode::SUCCESS) {
        IAM_LOGE("start process command fail ret = %{public}d", ret);
        return ret;
    }

    return command->GetResult();
}

ResultCode FrameworkExecutorCallback::ProcessGetTemplateCommand(
    std::shared_ptr<AuthAttributes> conditions, std::shared_ptr<AuthAttributes> values)
{
    IAM_LOGI("start");
    IF_FALSE_LOGE_AND_RETURN_VAL(conditions != nullptr, ResultCode::GENERAL_ERROR);
    IF_FALSE_LOGE_AND_RETURN_VAL(values != nullptr, ResultCode::GENERAL_ERROR);
    auto executor = executor_.lock();
    if (executor == nullptr) {
        IAM_LOGE("executor has been released, process failed");
        return ResultCode::GENERAL_ERROR;
    }
    auto hdi = executor->GetExecutorHdi();
    IF_FALSE_LOGE_AND_RETURN_VAL(hdi != nullptr, ResultCode::GENERAL_ERROR);
    uint64_t templateId = 0;
    conditions->GetUint64Value(AUTH_TEMPLATE_ID, templateId);
    TemplateInfo templateInfo = {};
    hdi->GetTemplateInfo(templateId, templateInfo);
    uint64_t subType = 0;
    Common::UnpackUint64(templateInfo.extraInfo, 0, subType);
    values->SetUint64Value(AUTH_SUBTYPE, subType);
    values->SetUint32Value(AUTH_REMAIN_TIME, templateInfo.freezingTime);
    values->SetUint32Value(AUTH_REMAIN_COUNT, templateInfo.remainTimes);
    return ResultCode::SUCCESS;
}

uint32_t FrameworkExecutorCallback::GenerateExecutorCallbackId()
{
    static std::mutex mutex;
    static uint32_t callbackId = 0;
    std::lock_guard<std::mutex> guard(mutex);
    // callbackId is only used in log, uint32 overflow or duplicate is ok
    ++callbackId;
    return callbackId;
}

const char *FrameworkExecutorCallback::GetDescription()
{
    return description_.c_str();
}
} // namespace UserAuth
} // namespace UserIAM
} // namespace OHOS
