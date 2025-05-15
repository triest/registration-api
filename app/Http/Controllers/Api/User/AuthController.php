<?php

namespace App\Http\Controllers\Api\User;


use App\Http\Controllers\Controller;
use App\Http\Requests\Registration\ReqistrationRequest;
use App\Models\User;
use Carbon\Carbon;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Hash;
use Illuminate\Validation\ValidationException;

class AuthController extends Controller
{
    public function register(ReqistrationRequest $request)
    {

        $validated = $request->validated();
        $user = User::create([
            'name' => $validated['name'],
            'email' => $validated['email'],
            'password' => Hash::make($validated['password']),
            'gender' => $validated['gender'],
        ]);

        $token = $user->createToken('auth_token')->plainTextToken;

        return response()->json([
            'access_token' => $token,
            'token_type' => 'Bearer',
        ]);
    }

    public function login(Request $request)
    {
        $request->validate([
            'email' => 'required|email',
            'password' => 'required',
        ]);

        $user = User::where('email', $request->email)->first();

        if (!$user || !Hash::check($request->password, $user->password)) {
            throw ValidationException::withMessages([
                'email' => ['The provided credentials are incorrect.'],
            ]);
        }

        $token = $user->createToken('auth_token',expiresAt:Carbon::now()->addSeconds(config('sanctum.expiration',500)))->plainTextToken;

        return response()->json([
            'access_token' => $token,
            'token_type' => 'Bearer',
        ]);
    }

    public function logout(Request $request)
    {
        $request->user()->currentAccessToken()->delete();

        return response()->json([
            'message' => 'Logged out'
        ]);
    }


    public function refreshToken(Request $request)
    {
        // Проверяем, не просрочен ли текущий токен
        if ($request->user()->currentAccessToken()->expires_at && $request->user()->currentAccessToken()->expires_at->isPast()) {
            // Удаляем просроченный токен
            $request->user()->currentAccessToken()->delete();

            // Создаем новый токен
            $newToken = $request->user()->createToken('auth_token', ['*'], now()->addMinutes(config('sanctum.expiration')))->plainTextToken;

            return response()->json([
                'access_token' => $newToken,
                'token_type' => 'Bearer',
                'expires_in' => config('sanctum.expiration') * 60, // В секундах
            ]);
        }

        // Если токен еще активен, возвращаем ошибку
        return response()->json(['message' => 'Token is still valid'], 400);
    }
}
