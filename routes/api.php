<?php

use App\Http\Controllers\Api\User\AuthController;
use App\Http\Controllers\Api\User\ProfileController;
use Illuminate\Support\Facades\Route;


Route::prefix('auth')->group(function () {



    Route::middleware('auth:sanctum')->group(function () {



    });
});
Route::post('/registration', [AuthController::class, 'register']);
Route::post('/login', [AuthController::class, 'login']);
Route::middleware('auth:sanctum')->group(function () {
    Route::get('/profile', [ProfileController::class, 'index']);
    Route::post('/logout', [AuthController::class, 'logout']);
    Route::post('/auth/refresh-token', [AuthController::class, 'refreshToken']);
});
