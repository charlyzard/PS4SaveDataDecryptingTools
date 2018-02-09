#pragma once

#include <types.h>

#define TRUE 1
#define FALSE 0

#define Inline static inline __attribute__((always_inline))

typedef char BOOL;
typedef unsigned char u8;
typedef unsigned short u16;

typedef int Any;
typedef unsigned int uint;
typedef int Hash;
typedef int Entity;
typedef int Player;
typedef int FireId;
typedef int Ped;
typedef int Vehicle;
typedef int Cam;
typedef int CarGenerator;
typedef int Group;
typedef int Train;
typedef int Pickup;
typedef int Object;
typedef int Weapon;
typedef int Interior;
typedef int Blip;
typedef int Texture;
typedef int TextureDict;
typedef int CoverPoint;
typedef int Camera;
typedef int TaskSequence;
typedef int ColourIndex;
typedef int Sphere;
typedef int ScrHandle;

typedef struct {
	float x, y, z;
} Vector3;

typedef struct {
	u8 r, g, b;
} Color;