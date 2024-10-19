// Copyright Ethan Porcaro

// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.

// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
// GNU General Public License for more details.

#include "BF2Service.h"
#include "SDK.h"
#include "Logging.h"
#include "ActionsService.h"
#include "D3DService.h"

namespace BF2VR {
    RenderView* BF2Service::CameraUpdate(RenderView* a1, RenderView* a2) {
        RenderView* toReturn = cameraUpdateHook.call<RenderView*>(a1, a2);

        if (!OpenXRService::xrRunning) {
            return toReturn;
        }

        GameRenderer* gameRenderer = GameRenderer::GetInstance();
        if (!isValidPtr(gameRenderer)) {
            return toReturn;
        }
        gameRenderer->gameRenderSettings->forceFov = 100;  // Fixes some occulsion culling stuff and reflections

        // Wrong camera to update
        if (a2 != reinterpret_cast<void*>(gameRenderer->renderView)) {
            return toReturn;
        }

        a2->transform = viewMatrix;

        // Get player position if player is even in the game
        bool soldierFound = false;
        GameContext* gameContext = GameContext::GetInstance();
        if (isValidPtr(gameContext)) {
            // Game context valid
            ClientPlayerManager* clientPlayerManager = gameContext->clientPlayerManager;
            if (isValidPtr(clientPlayerManager)) {
                // Player manager valid
                ClientPlayer* localPlayer = clientPlayerManager->localPlayer;
                if (isValidPtr(localPlayer)) {
                    // Local player valid
                    ClientControllableEntity* soldier = localPlayer->controlledcontrollable;
                    if (isValidPtr(soldier)) {
                        // Solider valid
                        ClientSoldierPrediction* soldierPrediction = soldier->clientSoldierPrediction;

                        if (isValidPtr(soldierPrediction)) {
                            a2->transform.o.x += soldierPrediction->location.x - .2f;  // 3rd person offset
                            a2->transform.o.y += soldierPrediction->location.y - soldier->HeightOffset + 3.1f;
                            a2->transform.o.z += soldierPrediction->location.z;

                            soldierFound = true;
                        }
                    }
                }
            }
        }
        inGame = soldierFound;

        // Disable TAA and local reflections
        WorldRenderSettings* worldRenderSettings = WorldRenderSettings::GetInstance();
        if (isValidPtr(worldRenderSettings)) {
            if (worldRenderSettings->aaDisocclusionFactor != 1.f) {
                worldRenderSettings->aaDisocclusionFactor = 1.f;
            }
            if (worldRenderSettings->localReflectionEnable) {
                worldRenderSettings->localReflectionEnable = false;
            }
            if (worldRenderSettings->motionBlurEnable) {
                worldRenderSettings->motionBlurEnable = false;
            }
            if (worldRenderSettings->skyLightingEnable) {
                worldRenderSettings->skyLightingEnable = false;
            }
            if (worldRenderSettings->outdoorLightEnable) {
                worldRenderSettings->outdoorLightEnable = false;
            }
        }

        // Set post options for the user
        if (isValidPtr(postSettings)) {
            postSettings->ScreenSpaceRaytraceEnable = false;
            postSettings->LensDistortionAllowed = false;
            postSettings->forceDofEnable = true;
            postSettings->forceDofBlurFactor = 0.f;
        }

        // Calculate aim angles
        const auto [hq0, hq1, hq2, hq3] = ActionsService::handLocations[1].pose.orientation;
        const auto [hlx, hly, hlz] = ActionsService::handLocations[1].pose.position;
        Vec3 aimEuler = eulerFromQuat({hq0, hq1, hq2, hq3});

        // Update aim angles
        LocalAimer* localAimer = LocalAimer::GetInstance();
        if (isValidPtr(localAimer)) {
            AimingComponentSwitch* viewAngleSwitch = localAimer->aimingComponentSwitch;
            if (isValidPtr(viewAngleSwitch)) {
                // Attempt to set the primary angle
                if (isValidPtr(viewAngleSwitch->primary)) {
                    // The correct viewangle will start with 12 0xff bytes
                    int i = 0;
                    while (i < 12) {
                        if (viewAngleSwitch->primary->signature[i] != 0xFF) {
                            break;
                        }
                        i++;
                    }
                    if (i == 12) {
                        viewAngleSwitch->primary->pitch = aimEuler.z - 1.22173f;
                        viewAngleSwitch->primary->yaw = -aimEuler.y + 3.14159f;
                        return toReturn;
                    }
                }

                // Attempt to set the secondary
                if (isValidPtr(viewAngleSwitch->secondary)) {
                    // The correct viewangle will start with 12 0xff bytes
                    int i = 0;
                    while (i < 12) {
                        if (viewAngleSwitch->secondary->signature[i] != 0xFF) {
                            break;
                        }
                        i++;
                    }
                    if (i == 12) {
                        viewAngleSwitch->secondary->pitch = aimEuler.z - 1.22173f;
                        viewAngleSwitch->secondary->yaw = -aimEuler.y + 3.14159f;
                        return toReturn;
                    }
                }
            }
        }

        // Aim was not set
        return toReturn;
    }

    void BF2Service::BuildViews(RenderView* view) {
        if (!OpenXRService::xrRunning) {
            return;
        }

        view->projectionMatrix = projMatrix;
        view->orthoWidth = static_cast<float>(OpenXRService::swapchainWidth);
        view->orthoHeight = static_cast<float>(OpenXRService::swapchainHeight);
        view->aspectRatio = static_cast<float>(OpenXRService::swapchainWidth) / static_cast<float>(OpenXRService::swapchainHeight);
    }

    void BF2Service::GamepadUpdate(GamepadState* state) {
        if (!isValidPtr(state)) {
            return;
        }

        state->bitmask = 0x0000;
        if (ActionsService::jumpValue.currentState) {
            state->bitmask |= 0x0020;  // A
        }
        if (ActionsService::rollValue.currentState) {
            state->bitmask |= 0x0080;  // B
        }
        if (ActionsService::basicValue.currentState) {
            state->bitmask |= 0x0040;  // X
        }
        if (ActionsService::reloadValue.currentState) {
            state->bitmask |= 0x0010;  // Y
        }
        if (ActionsService::triggerValue[0].currentState) {
            state->bitmask |= 0x0400;  // L3
        }
        if (ActionsService::gripValue[0].currentState) {
            state->bitmask |= 0x10000;  // LB
        }
        if (ActionsService::gripValue[1].currentState) {
            state->bitmask |= 0x20000;  // RB
        }

        state->LeftThumb.x = ActionsService::walkValue.currentState.x;
        state->LeftThumb.y = ActionsService::walkValue.currentState.y;
        state->RT = ActionsService::triggerValue[1].currentState;
    }

    int BF2Service::Initialize() {
        cameraUpdateHook = safetyhook::create_inline(reinterpret_cast<void*>(OFFSETCAMERA), reinterpret_cast<void*>(CameraUpdate));
        if (!cameraUpdateHook) {
            Logging::Log("[BF2] Camera hook failed to install");
            return -1;
        }


        safetyhook::MidHookFn buildViewsFn = [](safetyhook::Context& ctx) {
            BuildViews(reinterpret_cast<RenderView*>(ctx.rbx));
        };
        buildViewsHook = safetyhook::create_mid(reinterpret_cast<void*>(OFFSETBUILDVIEWS), buildViewsFn);
        if (!buildViewsHook) {
            Logging::Log("[BF2] Viewbuilder hook failed to install");
            return -1;
        }


        safetyhook::MidHookFn resizeScreenFn = [](safetyhook::Context& ctx) {
            Screen* screen = reinterpret_cast<Screen*>(ctx.rbx);
            screen->bufferWidth = OpenXRService::swapchainWidth;
            screen->bufferHeight = OpenXRService::swapchainHeight;
        };
        resizeScreenHook = safetyhook::create_mid(reinterpret_cast<void*>(OFFSETRESIZESCREEN), resizeScreenFn);
        if (!resizeScreenHook) {
            Logging::Log("[BF2] Screen resizer hook failed to install");
            return -1;
        }

        safetyhook::MidHookFn postFn = [](safetyhook::Context& ctx) {
            GlobalPostProcessSettings* settings = reinterpret_cast<GlobalPostProcessSettings*>(ctx.r8);
            if (isValidPtr(postSettings)) {
                return;
            }
            if (isValidPtr(settings)) {
                postSettings = settings;
            }
        };
        postHook = safetyhook::create_mid(reinterpret_cast<void*>(OFFSETPOST), postFn);
        if (!postHook) {
            Logging::Log("[BF2] Post processing hook failed to install");
            return -1;
        }

        safetyhook::MidHookFn gamepadUpdateFn = [](safetyhook::Context& ctx) {
            GamepadUpdate(reinterpret_cast<GamepadState*>(ctx.rbx));
        };
        gamepadHook = safetyhook::create_mid(reinterpret_cast<void*>(OFFSETGAMEPADUPDATE), gamepadUpdateFn);
        if (!gamepadHook) {
            Logging::Log("[BF2] Gamepad hook failed to install.");
            return -1;
        }

        return 0;
    }

    int BF2Service::Uninitialize() {
        cameraUpdateHook = {};
        buildViewsHook = {};
        resizeScreenHook = {};
        postHook = {};
        gamepadHook = {};

        Logging::Log("[BF2] Hooks removed");

        GameRenderer* gameRenderer = GameRenderer::GetInstance();
        if (!isValidPtr(gameRenderer)) {
            Logging::Log("[BF2] Unable to restore FOV");
        } else {
            gameRenderer->gameRenderSettings->forceFov = -1;
        }

        if (isValidPtr(postSettings)) {
            postSettings->forceDofEnable = false;
            postSettings->ScreenSpaceRaytraceEnable = true;
        }

        return 0;
    }
}  // namespace BF2VR
