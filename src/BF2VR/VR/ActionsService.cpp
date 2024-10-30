// Copyright Ethan Porcaro

// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.

// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
// GNU General Public License for more details.

#include <ActionsService.h>
#include <OpenXRService.h>
#include <vector>
#include <Logging.h>

namespace BF2VR {
int ActionsService::Initialize() {
    // Create main action set
    XrActionSetCreateInfo actionSetInfo = { XR_TYPE_ACTION_SET_CREATE_INFO };
    actionSetInfo.priority = 0;
    strcpy_s(actionSetInfo.actionSetName, "gameplay");
    strcpy_s(actionSetInfo.localizedActionSetName, "Gameplay");

    XrResult xr = xrCreateActionSet(OpenXRService::xrInstance, &actionSetInfo, &actionSet);
    if (xr != XR_SUCCESS) {
        Logging::Log("[Actions] Failed to create action set", xr);
        return -1;
    }


    // Hands pose action
    xrStringToPath(OpenXRService::xrInstance, "/user/hand/left", &handPaths[0]);
    xrStringToPath(OpenXRService::xrInstance, "/user/hand/right", &handPaths[1]);
    {
        XrActionCreateInfo actionInfo = { XR_TYPE_ACTION_CREATE_INFO };
        actionInfo.actionType = XR_ACTION_TYPE_POSE_INPUT;
        actionInfo.countSubactionPaths = 2;
        actionInfo.subactionPaths = handPaths.data();
        strcpy_s(actionInfo.actionName, "handpose");
        strcpy_s(actionInfo.localizedActionName, "Hand Pose");
        xr = xrCreateAction(actionSet, &actionInfo, &poseAction);
        if (xr != XR_SUCCESS) {
            Logging::Log("[Actions] Failed to create pose for hands", xr);
            return -1;
        }
    }

    // Hand click action
    xrStringToPath(OpenXRService::xrInstance, "/user/hand/left/input/trigger/value", &triggerPaths[0]);
    xrStringToPath(OpenXRService::xrInstance, "/user/hand/right/input/trigger/value", &triggerPaths[1]);
    {
        XrActionCreateInfo actionInfo = { XR_TYPE_ACTION_CREATE_INFO };
        actionInfo.actionType = XR_ACTION_TYPE_FLOAT_INPUT;
        actionInfo.countSubactionPaths = 2;
        actionInfo.subactionPaths = handPaths.data();
        strcpy_s(actionInfo.actionName, "firefloat");
        strcpy_s(actionInfo.localizedActionName, "Fire Gun");
        xr = xrCreateAction(actionSet, &actionInfo, &triggerAction);
        if (xr != XR_SUCCESS) {
            Logging::Log("[Actions] Failed to create action for trigger", xr);
            return -1;
        }
    }

    // Hand grip
    xrStringToPath(OpenXRService::xrInstance, "/user/hand/left/input/squeeze/value", &gripPaths[0]);
    xrStringToPath(OpenXRService::xrInstance, "/user/hand/right/input/squeeze/value", &gripPaths[1]);
    {
        XrActionCreateInfo actionInfo = { XR_TYPE_ACTION_CREATE_INFO };
        actionInfo.actionType = XR_ACTION_TYPE_FLOAT_INPUT;
        actionInfo.countSubactionPaths = 2;
        actionInfo.subactionPaths = handPaths.data();
        strcpy_s(actionInfo.actionName, "grip");
        strcpy_s(actionInfo.localizedActionName, "Left Right and Middle Abilities");
        xr = xrCreateAction(actionSet, &actionInfo, &gripAction);
        if (xr != XR_SUCCESS) {
            Logging::Log("[Actions] Failed to create action for grip", xr);
            return -1;
        }
    }

    // Menu click action
    xrStringToPath(OpenXRService::xrInstance, "/user/hand/left/input/y/click", &basicPath);
    {
        XrActionCreateInfo actionInfo = { XR_TYPE_ACTION_CREATE_INFO };
        actionInfo.actionType = XR_ACTION_TYPE_BOOLEAN_INPUT;
        actionInfo.countSubactionPaths = 1;
        actionInfo.subactionPaths = &handPaths[0];
        strcpy_s(actionInfo.actionName, "basic");
        strcpy_s(actionInfo.localizedActionName, "Basic weapon");
        xr = xrCreateAction(actionSet, &actionInfo, &basicAction);
        if (xr != XR_SUCCESS) {
            Logging::Log("[Actions] Failed to create action for basic weapon", xr);
            return -1;
        }
    }

    // X click action
    xrStringToPath(OpenXRService::xrInstance, "/user/hand/left/input/x/click", &reloadPath);
    {
        XrActionCreateInfo actionInfo = { XR_TYPE_ACTION_CREATE_INFO };
        actionInfo.actionType = XR_ACTION_TYPE_BOOLEAN_INPUT;
        actionInfo.countSubactionPaths = 1;
        actionInfo.subactionPaths = &handPaths[0];
        strcpy_s(actionInfo.actionName, "reload");
        strcpy_s(actionInfo.localizedActionName, "Reload");
        xr = xrCreateAction(actionSet, &actionInfo, &reloadAction);
        if (xr != XR_SUCCESS) {
            Logging::Log("[Actions] Failed to create action for menu", xr);
            return -1;
        }
    }

    // Battle roll action
    xrStringToPath(OpenXRService::xrInstance, "/user/hand/right/input/b/click", &rollPath);
    {
        XrActionCreateInfo actionInfo = { XR_TYPE_ACTION_CREATE_INFO };
        actionInfo.actionType = XR_ACTION_TYPE_BOOLEAN_INPUT;
        actionInfo.countSubactionPaths = 1;
        actionInfo.subactionPaths = &handPaths[1];
        strcpy_s(actionInfo.actionName, "roll");
        strcpy_s(actionInfo.localizedActionName, "Battle Roll");
        xr = xrCreateAction(actionSet, &actionInfo, &rollAction);
        if (xr != XR_SUCCESS) {
            Logging::Log("[Actions] Failed to create action for battle roll", xr);
            return -1;
        }
    }

    // Jump Action
    xrStringToPath(OpenXRService::xrInstance, "/user/hand/right/input/a/click", &jumpPath);
    {
        XrActionCreateInfo actionInfo = { XR_TYPE_ACTION_CREATE_INFO };
        actionInfo.actionType = XR_ACTION_TYPE_BOOLEAN_INPUT;
        actionInfo.countSubactionPaths = 1;
        actionInfo.subactionPaths = &handPaths[1];
        strcpy_s(actionInfo.actionName, "jump");
        strcpy_s(actionInfo.localizedActionName, "Jump");
        xr = xrCreateAction(actionSet, &actionInfo, &jumpAction);
        if (xr != XR_SUCCESS) {
            Logging::Log("[Actions] Failed to create action for jump", xr);
            return -1;
        }
    }

    // Walking (left thumbstick) action
    xrStringToPath(OpenXRService::xrInstance, "/user/hand/left/input/thumbstick", &walkPath);
    {
        XrActionCreateInfo actionInfo = { XR_TYPE_ACTION_CREATE_INFO };
        actionInfo.actionType = XR_ACTION_TYPE_VECTOR2F_INPUT;
        actionInfo.countSubactionPaths = 1;
        actionInfo.subactionPaths = &handPaths[0];
        strcpy_s(actionInfo.actionName, "walk");
        strcpy_s(actionInfo.localizedActionName, "Walk");
        xr = xrCreateAction(actionSet, &actionInfo, &walkAction);
        if (xr != XR_SUCCESS) {
            Logging::Log("[Actions] Failed to create action for walking", xr);
            return -1;
        }
    }

    // Looking (right thumbstick) action
    xrStringToPath(OpenXRService::xrInstance, "/user/hand/right/input/thumbstick", &lookPath);
    {
        XrActionCreateInfo actionInfo = { XR_TYPE_ACTION_CREATE_INFO };
        actionInfo.actionType = XR_ACTION_TYPE_VECTOR2F_INPUT;
        actionInfo.countSubactionPaths = 1;
        actionInfo.subactionPaths = &handPaths[0];
        strcpy_s(actionInfo.actionName, "look");
        strcpy_s(actionInfo.localizedActionName, "Look/Menu");
        xr = xrCreateAction(actionSet, &actionInfo, &lookAction);
        if (xr != XR_SUCCESS) {
            Logging::Log("[Actions] Failed to create action for looking", xr);
            return -1;
        }
    }

    // Suggest interaction profile
    XrPath gripPosePath[2];
    xrStringToPath(OpenXRService::xrInstance, "/user/hand/left/input/grip/pose", &gripPosePath[0]);
    xrStringToPath(OpenXRService::xrInstance, "/user/hand/right/input/grip/pose", &gripPosePath[1]);


    XrPath interactionProfilePath;
    xr = xrStringToPath(OpenXRService::xrInstance, "/interaction_profiles/oculus/touch_controller", &interactionProfilePath);
    if (xr != XR_SUCCESS) {
        Logging::Log("[Actions] Failed to get interaction profile", xr);
        return -1;
    }

    // Set bindings
    std::vector<XrActionSuggestedBinding> bindings;
    XrActionSuggestedBinding binding;
    binding.action = poseAction;
    binding.binding = gripPosePath[0];
    bindings.push_back(binding);
    binding.action = poseAction;
    binding.binding = gripPosePath[1];
    bindings.push_back(binding);

    binding.action = triggerAction;
    binding.binding = triggerPaths[0];
    bindings.push_back(binding);
    binding.action = triggerAction;
    binding.binding = triggerPaths[1];
    bindings.push_back(binding);

    binding.action = gripAction;
    binding.binding = gripPaths[0];
    bindings.push_back(binding);
    binding.action = gripAction;
    binding.binding = gripPaths[1];
    bindings.push_back(binding);

    binding.action = basicAction;
    binding.binding = basicPath;
    bindings.push_back(binding);

    binding.action = walkAction;
    binding.binding = walkPath;
    bindings.push_back(binding);

    binding.action = rollAction;
    binding.binding = rollPath;
    bindings.push_back(binding);

    binding.action = jumpAction;
    binding.binding = jumpPath;
    bindings.push_back(binding);

    binding.action = reloadAction;
    binding.binding = reloadPath;
    bindings.push_back(binding);

    // Rehister bindings
    XrInteractionProfileSuggestedBinding suggestedBindings = { XR_TYPE_INTERACTION_PROFILE_SUGGESTED_BINDING };
    suggestedBindings.interactionProfile = interactionProfilePath;
    suggestedBindings.countSuggestedBindings = bindings.size();
    suggestedBindings.suggestedBindings = bindings.data();

    xrSuggestInteractionProfileBindings(OpenXRService::xrInstance, &suggestedBindings);
    if (xr != XR_SUCCESS) {
        Logging::Log("[Actions] Failed to suggest bindings", xr);
        return -1;
    }

    // Attach actions
    XrSessionActionSetsAttachInfo actionsetAttachInfo = { XR_TYPE_SESSION_ACTION_SETS_ATTACH_INFO };
    actionsetAttachInfo.countActionSets = 1;
    actionsetAttachInfo.actionSets = &actionSet;
    xr = xrAttachSessionActionSets(OpenXRService::xrSession, &actionsetAttachInfo);
    if (xr != XR_SUCCESS) {
        Logging::Log("[Actions] Failed to attach action set", xr);
        return -1;
    }

    // Create hand pose spaces
    {
        XrActionSpaceCreateInfo actionSpaceInfo = { XR_TYPE_ACTION_SPACE_CREATE_INFO };
        actionSpaceInfo.action = poseAction;
        actionSpaceInfo.poseInActionSpace = { { 0, 0, 0, 1 }, { 0, 0, 0 } };
        actionSpaceInfo.subactionPath = handPaths[0];

        xr = xrCreateActionSpace(OpenXRService::xrSession, &actionSpaceInfo, &poseActionSpaces[0]);
        if (xr != XR_SUCCESS) {
            Logging::Log("[Actions] Failed to create left hand pose space", xr);
            return -1;
        }
    }

    {
        XrActionSpaceCreateInfo actionSpaceInfo = { XR_TYPE_ACTION_SPACE_CREATE_INFO };
        actionSpaceInfo.action = poseAction;
        actionSpaceInfo.poseInActionSpace = { { 0, 0, 0, 1 }, { 0, 0, 0 } };
        actionSpaceInfo.subactionPath = handPaths[1];

        xr = xrCreateActionSpace(OpenXRService::xrSession, &actionSpaceInfo, &poseActionSpaces[1]);
        if (xr != XR_SUCCESS) {
            Logging::Log("[Actions] Failed to create right hand pose space", xr);
            return -1;
        }
    }

    Logging::Log("[Actions] Actions created");
    return 0;
}

void ActionsService::SyncActions() {
    if (!OpenXRService::xrRunning) {
        return;
    }

    // Sync actions
    XrActiveActionSet activeActionsets = { actionSet, XR_NULL_PATH };
    XrActionsSyncInfo actionsSyncInfo = { XR_TYPE_ACTIONS_SYNC_INFO };
    actionsSyncInfo.countActiveActionSets = 1;
    actionsSyncInfo.activeActionSets = &activeActionsets;

    XrResult xr = xrSyncActions(OpenXRService::xrSession, &actionsSyncInfo);
    if (xr != XR_SUCCESS && xr != XR_SESSION_NOT_FOCUSED) {
        return;
    }

    // Get hand poses
    for (int i = 0; i < 2; i++) {
        {
            XrActionStatePose pose_state = { XR_TYPE_ACTION_STATE_POSE };
            XrActionStateGetInfo getInfo = { XR_TYPE_ACTION_STATE_GET_INFO };
            getInfo.action = poseAction;
            getInfo.subactionPath = handPaths[i];
            xr = xrGetActionStatePose(OpenXRService::xrSession, &getInfo, &pose_state);
            if (xr != XR_SUCCESS) {
                return;
            }

            handLocations[i].type = XR_TYPE_SPACE_LOCATION;

            xr = xrLocateSpace(poseActionSpaces[i], OpenXRService::xrSpace, OpenXRService::xrFrameState.predictedDisplayTime, &handLocations[i]);
            if (xr != XR_SUCCESS) {
                return;
            }
        }
        {
            // Get controller trigger states
            triggerValue[i].type = XR_TYPE_ACTION_STATE_FLOAT;

            XrActionStateGetInfo getInfo = { XR_TYPE_ACTION_STATE_GET_INFO };
            getInfo.action = triggerAction;
            getInfo.subactionPath = handPaths[i];
            xr = xrGetActionStateFloat(OpenXRService::xrSession, &getInfo, &triggerValue[i]);
            if (xr != XR_SUCCESS) {
                return;
            }
        }
        {
            // Get controller trigger states
            gripValue[i].type = XR_TYPE_ACTION_STATE_FLOAT;

            XrActionStateGetInfo getInfo = { XR_TYPE_ACTION_STATE_GET_INFO };
            getInfo.action = gripAction;
            getInfo.subactionPath = handPaths[i];
            xr = xrGetActionStateFloat(OpenXRService::xrSession, &getInfo, &gripValue[i]);
            if (xr != XR_SUCCESS) {
                return;
            }
        }
    }

    {
        // Get basic weapon button state
        basicValue.type = XR_TYPE_ACTION_STATE_BOOLEAN;

        XrActionStateGetInfo getInfo = { XR_TYPE_ACTION_STATE_GET_INFO };
        getInfo.action = basicAction;
        getInfo.subactionPath = handPaths[0];
        xr = xrGetActionStateBoolean(OpenXRService::xrSession, &getInfo, &basicValue);
        if (xr != XR_SUCCESS) {
            return;
        }
    }

    {
        // Get roll button state
        rollValue.type = XR_TYPE_ACTION_STATE_BOOLEAN;

        XrActionStateGetInfo getInfo = { XR_TYPE_ACTION_STATE_GET_INFO };
        getInfo.action = rollAction;
        getInfo.subactionPath = handPaths[1];
        xr = xrGetActionStateBoolean(OpenXRService::xrSession, &getInfo, &rollValue);
        if (xr != XR_SUCCESS) {
            return;
        }
    }

    {
        // Get jump button state
        jumpValue.type = XR_TYPE_ACTION_STATE_BOOLEAN;

        XrActionStateGetInfo getInfo = { XR_TYPE_ACTION_STATE_GET_INFO };
        getInfo.action = jumpAction;
        getInfo.subactionPath = handPaths[1];
        xr = xrGetActionStateBoolean(OpenXRService::xrSession, &getInfo, &jumpValue);
        if (xr != XR_SUCCESS) {
            return;
        }
    }

    {
        // Get reload button state
        reloadValue.type = XR_TYPE_ACTION_STATE_BOOLEAN;

        XrActionStateGetInfo getInfo = { XR_TYPE_ACTION_STATE_GET_INFO };
        getInfo.action = reloadAction;
        getInfo.subactionPath = handPaths[0];
        xr = xrGetActionStateBoolean(OpenXRService::xrSession, &getInfo, &reloadValue);
        if (xr != XR_SUCCESS) {
            return;
        }
    }

    {
        // Get walking state
        walkValue.type = XR_TYPE_ACTION_STATE_VECTOR2F;

        XrActionStateGetInfo getInfo = { XR_TYPE_ACTION_STATE_GET_INFO };
        getInfo.action = walkAction;
        getInfo.subactionPath = handPaths[0];
        xr = xrGetActionStateVector2f(OpenXRService::xrSession, &getInfo, &walkValue);
        if (xr != XR_SUCCESS) {
            return;
        }
    }

    {
        // Get looking state
        lookValue.type = XR_TYPE_ACTION_STATE_VECTOR2F;

        XrActionStateGetInfo getInfo = { XR_TYPE_ACTION_STATE_GET_INFO };
        getInfo.action = lookAction;
        getInfo.subactionPath = handPaths[0];
        xr = xrGetActionStateVector2f(OpenXRService::xrSession, &getInfo, &lookValue);
        if (xr != XR_SUCCESS) {
            return;
        }
    }
}
}  // namespace BF2VR
