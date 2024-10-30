#pragma once
// Copyright Ethan Porcaro

// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.

// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
// GNU General Public License for more details.

#include <openxr/openxr.h>
#include <openxr/openxr_platform.h>
#include <array>

namespace BF2VR {

class ActionsService {
 public:
    static int Initialize();
    static void SyncActions();

    // PrepareActions
    static inline XrActionSet actionSet;

    static inline std::array<XrPath, 2> handPaths;
    static inline std::array<XrPath, 2> triggerPaths;
    static inline std::array<XrPath, 2> gripPaths;
    static inline XrPath basicPath;
    static inline XrPath rollPath;
    static inline XrPath jumpPath;
    static inline XrPath reloadPath;
    static inline XrPath walkPath;
    static inline XrPath lookPath;

    static inline XrAction poseAction;
    static inline XrAction triggerAction;
    static inline XrAction gripAction;
    static inline XrAction basicAction;
    static inline XrAction rollAction;
    static inline XrAction jumpAction;
    static inline XrAction reloadAction;
    static inline XrAction walkAction;
    static inline XrAction lookAction;

    static inline XrSpace poseActionSpaces[2];

    // Action values
    static inline XrSpaceLocation handLocations[2];
    static inline XrActionStateFloat triggerValue[2];
    static inline XrActionStateFloat gripValue[2];
    static inline XrActionStateBoolean basicValue;
    static inline XrActionStateBoolean rollValue;
    static inline XrActionStateBoolean jumpValue;
    static inline XrActionStateBoolean reloadValue;

    static inline XrActionStateVector2f walkValue;
    static inline XrActionStateVector2f lookValue;
};

}  // namespace BF2VR
