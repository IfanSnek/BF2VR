// Copyright Ethan Porcaro

// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.

// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
// GNU General Public License for more details.

#pragma once
#include "SDK.h"
#include <safetyhook.hpp>
#include <Xinput.h>


namespace BF2VR {

class BF2Service {
 public:
    static int Initialize();
    static int Uninitialize();
    static inline Matrix4 viewMatrix;
    static inline Matrix4 projMatrix;
    static inline XINPUT_GAMEPAD gamepad;
    static inline bool inGame = false;

 private:
    static inline GlobalPostProcessSettings* postSettings;

    static inline SafetyHookInline cameraUpdateHook;
    static RenderView* CameraUpdate(RenderView* a1, RenderView* a2);

    static inline SafetyHookMid buildViewsHook;
    static void BuildViews(RenderView* view);

    static inline SafetyHookMid resizeScreenHook;

    static inline SafetyHookMid postHook;

    static inline SafetyHookMid gamepadHook;
    static void GamepadUpdate(GamepadState* state);
};

}  // namespace BF2VR
