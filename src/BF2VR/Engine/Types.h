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
#include <openxr/openxr.h>
#include <format>
#include <cmath>
#include <string>

struct Vec2 {
    float x;
    float y;
};

struct Vec3 {
    float x;
    float y;
    float z;

    Vec3 operator+(Vec3 v2) const {
        v2.x += x;
        v2.y += y;
        v2.z += z;

        return v2;
    }

    Vec3 operator*(Vec3 v2) const {
        v2.x *= x;
        v2.y *= y;
        v2.z *= z;

        return v2;
    }

    Vec3 operator-(Vec3 v2) const {
        Vec3 v1 = Vec3(x, y, z);
        v1.x -= v2.x;
        v1.y -= v2.y;
        v1.z -= v2.z;

        return v1;
    }

    std::string toString() {
        return std::format("X={:.4f} Y={:.4f} Z={:.4f}", x, y, z);
    }
};

struct Vec4 {
    float x;
    float y;
    float z;
    float w;

    Vec4 rotateByEuler(float eulerX, float eulerY, float eulerZ) {
        // Convert Euler angles to quaternion
        Vec4 eulerQuat{};
        float cosX = cos(eulerX / 2);
        float sinX = sin(eulerX / 2);
        float cosY = cos(eulerY / 2);
        float sinY = sin(eulerY / 2);
        float cosZ = cos(eulerZ / 2);
        float sinZ = sin(eulerZ / 2);
        eulerQuat.w = cosX * cosY * cosZ + sinX * sinY * sinZ;
        eulerQuat.x = sinX * cosY * cosZ - cosX * sinY * sinZ;
        eulerQuat.y = cosX * sinY * cosZ + sinX * cosY * sinZ;
        eulerQuat.z = cosX * cosY * sinZ - sinX * sinY * cosZ;

        // Multiply original quaternion by Euler angle quaternion to apply rotation
        Vec4 rotatedQuat;
        rotatedQuat.w = w * eulerQuat.w - x * eulerQuat.x - y * eulerQuat.y - z * eulerQuat.z;
        rotatedQuat.x = w * eulerQuat.x + x * eulerQuat.w + y * eulerQuat.z - z * eulerQuat.y;
        rotatedQuat.y = w * eulerQuat.y - x * eulerQuat.z + y * eulerQuat.w + z * eulerQuat.x;
        rotatedQuat.z = w * eulerQuat.z + x * eulerQuat.y - y * eulerQuat.x + z * eulerQuat.w;

        return rotatedQuat;
    }

    Vec4 operator*(Vec4 v2) const {
        Vec4 v1 = Vec4(x, y, z, w);
        v1.x *= v2.x;
        v1.y *= v2.y;
        v1.z *= v2.z;
        v1.w *= v2.w;

        return v1;
    }

    Vec4 operator/(Vec4 v2) const {
        Vec4 v1 = Vec4(x, y, z, w);
        v1.x /= v2.x;
        v1.y /= v2.y;
        v1.z /= v2.z;
        v1.w /= v2.w;

        return v1;
    }

    Vec4 operator+(Vec4 v2) const {
        v2.x += x;
        v2.y += y;
        v2.z += z;
        v2.w += w;

        return v2;
    }

    Vec3 dropW() const {
        return Vec3(x, y, z);
    }

    std::string toString() {
        return std::format("X={:.4f} Y={:.4f} Z={:.4f} W={:.4f}", x, y, z, w);
    }
};

static inline Vec3 rotateAround(Vec3 point, Vec3 pivot, float rad) {
    Vec3 out = Vec3(point);

    out.x = pivot.x + (cos(rad) * (point.x - pivot.x)) - (sin(rad) * (point.z - pivot.z));
    out.z = pivot.z + (sin(rad) * (point.x - pivot.x)) + (cos(rad) * (point.z - pivot.z));

    return out;
}

static inline Vec4 appendW(Vec3 v2, float w = 0.f) {
    Vec4 v1{};
    v1.x = v2.x;
    v1.y = v2.y;
    v1.z = v2.z;
    v1.w = w;
    return v1;
}

struct Matrix4 {
    Vec4 x;
    Vec4 y;
    Vec4 z;
    Vec4 o;

    Matrix4 operator*(Matrix4 m2) const {
        Matrix4 m1 = Matrix4(x, y, z, o);
        m1.x = m1.x * m2.x;
        m1.y = m1.y * m2.y;
        m1.z = m1.z * m2.z;
        m1.o = m1.o * m2.o;

        return m1;
    }

    std::string ToString() {
        return std::format("X={}\nY={}\nZ={}\nO={}", x.toString(), y.toString(), z.toString(), o.toString());
    }
};


static inline Matrix4 fromOpenXR(XrView view) {
    const auto [q1, q2, q3, q0] = view.pose.orientation;
    const auto [lx, ly, lz] = view.pose.position;

    Matrix4 matrix{};

    matrix.x.x = 2 * (q0 * q0 + q1 * q1) - 1;
    matrix.y.x = 2 * (q1 * q2 - q0 * q3);
    matrix.z.x = 2 * (q1 * q3 + q0 * q2);
    matrix.o.x = lx;

    matrix.x.y = 2 * (q1 * q2 + q0 * q3);
    matrix.y.y = 2 * (q0 * q0 + q2 * q2) - 1;
    matrix.z.y = 2 * (q2 * q3 - q0 * q1);
    matrix.o.y = ly;

    matrix.x.z = 2 * (q1 * q3 - q0 * q2);
    matrix.y.z = 2 * (q2 * q3 + q0 * q1);
    matrix.z.z = 2 * (q0 * q0 + q3 * q3) - 1;
    matrix.o.z = lz;

    matrix.x.w = 0;
    matrix.y.w = 0;
    matrix.z.w = 0;
    matrix.o.w = 1;

    return matrix;
}

static inline Matrix4 fromFOV(float l, float r, float u, float d) {
    const float n = 0.06f;

    l = n * tanf(l);
    r = n * tanf(r);
    u = n * tanf(u);
    d = n * tanf(d);

    const float w = 1.f / (r - l);
    const float h = 1.f / (u - d);

    Matrix4 matrix{};

    matrix.x.x = 2 * n * w;
    matrix.y.x = 0;
    matrix.z.x = (l + r) * w;
    matrix.o.x = 0;

    matrix.x.y = 0;
    matrix.y.y = 2 * n * h;
    matrix.z.y = (u + d) * h;
    matrix.o.y = 0;

    matrix.x.z = 0;
    matrix.y.z = 0;
    matrix.z.z = 0;
    matrix.o.z = n;

    matrix.x.w = 0;
    matrix.y.w = 0;
    matrix.z.w = -1;
    matrix.o.w = 0;

    return matrix;
}

// Converts quats to euler for the Aiming function
static inline Vec3 eulerFromQuat(Vec4 q) {
    Vec3 v;

    float test = q.x * q.y + q.z * q.w;
    if (test > 0.499) {  // singularity at north pole
        v.x = 2 * atan2(q.x, q.w);  // heading
        v.y = -3.141592 / 2;  // attitude
        v.z = 0;  // bank
        return v;
    }
    if (test < -0.499) {  // singularity at south pole
        v.x = -2 * atan2(q.x, q.w);  // headingq
        v.y = -3.141592 / 2;  // attitude
        v.z = 0;  // bank
        return v;
    }
    float sqx = q.x * q.x;
    float sqy = q.y * q.y;
    float sqz = q.z * q.z;
    v.y = atan2(2 * q.y * q.w - 2 * q.x * q.z, 1 - 2 * sqy - 2 * sqz);  // heading
    v.x = asin(2 * test);  // attitude
    v.z = atan2(2 * q.x * q.w - 2 * q.y * q.z, 1 - 2 * sqx - 2 * sqz);  // bank
    return v;
}
