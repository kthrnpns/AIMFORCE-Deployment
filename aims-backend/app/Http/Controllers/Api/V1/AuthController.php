<?php

namespace App\Http\Controllers\Api\V1;

use App\Http\Controllers\Controller;
use App\Models\User;
use Illuminate\Http\JsonResponse;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Hash;
use Illuminate\Support\Facades\Log;
use Illuminate\Support\Facades\Mail;
use Illuminate\Validation\Rule;

class AuthController extends Controller
{
    public function login(Request $request): JsonResponse
    {
        $request->validate([
            'email' => 'required|email',
            'password' => 'required',
        ]);

        $user = User::where('email', $request->email)->first();

        if (! $user || ! Hash::check($request->password, $user->password)) {
            return response()->json(['message' => 'Invalid credentials.'], 401);
        }

        if (! $user->is_active) {
            return response()->json(['message' => 'This account is deactivated. Contact the administrator.'], 403);
        }

        // Generate 6-digit MFA Code (valid for 5 minutes)
        $mfaCode = (string) random_int(100000, 999999);
        $user->forceFill([
            'mfa_code' => Hash::make($mfaCode),
            'mfa_expires_at' => now()->addMinutes(5),
        ])->save();

        // On a developer's machine the code is logged and shown on screen; everywhere else it is only emailed.
        $local = app()->environment('local', 'testing');
        if ($local) {
            Log::info("MFA Code for {$user->email}: {$mfaCode}");
        }

        try {
            Mail::raw(
                "Your AIMS sign-in code is {$mfaCode}. It expires in 5 minutes.\n\nIf you did not try to sign in, change your password.",
                fn ($m) => $m->to($user->email)->subject('Your AIMS sign-in code')
            );
        } catch (\Throwable $e) {
            report($e);
            if (! $local) {
                return response()->json(['message' => 'We could not send your sign-in code. Try again later or contact the administrator.'], 503);
            }
        }

        return response()->json([
            'mfa_required' => true,
            'email' => $user->email,
            'message' => 'We emailed you a 6-digit sign-in code.',
            ...($local ? ['dev_code' => $mfaCode] : []),
        ]);
    }

    public function verifyMfa(Request $request): JsonResponse
    {
        $request->validate([
            'email' => 'required|email',
            'code' => 'required|string|size:6',
        ]);

        $user = User::where('email', $request->email)->first();

        if (! $user || ! $user->mfa_code || ! $user->mfa_expires_at) {
            return response()->json(['message' => 'No active MFA request found. Please sign in again.'], 400);
        }

        if (now()->greaterThan($user->mfa_expires_at)) {
            return response()->json(['message' => 'MFA code has expired. Please sign in again.'], 422);
        }

        if (! Hash::check($request->code, $user->mfa_code)) {
            return response()->json(['message' => 'Invalid verification code.'], 422);
        }

        // Clear MFA code and update last login timestamp after successful verification
        $user->forceFill([
            'mfa_code' => null,
            'mfa_expires_at' => null,
            'last_login_at' => now(),
        ])->save();

        $token = $user->createToken('auth_token')->plainTextToken;

        return response()->json([
            'token' => $token,
            'access_token' => $token,
            'token_type' => 'Bearer',
            'user' => $this->payload($user),
        ]);
    }

    // Public sign-up. Self-registered accounts are always clients; staff roles are assigned by an admin.
    public function register(Request $request): JsonResponse
    {
        $data = $request->validate([
            'name' => 'required|string|max:255',
            'email' => 'required|email|max:255|unique:users,email',
            'password' => 'required|string|min:8|confirmed',
            'organization' => 'nullable|string|max:255',
            'phone' => 'nullable|string|max:40',
        ]);

        $user = User::create([
            'name' => $data['name'],
            'email' => $data['email'],
            'password' => $data['password'], // hashed by the model cast
            'organization' => $data['organization'] ?? null,
            'phone' => $data['phone'] ?? null,
        ]);
        $user->assignRole('client');

        $token = $user->createToken('auth_token')->plainTextToken;

        return response()->json([
            'token' => $token,
            'access_token' => $token,
            'token_type' => 'Bearer',
            'user' => $this->payload($user),
        ], 201);
    }

    public function updateProfile(Request $request): JsonResponse
    {
        $user = $request->user();

        $data = $request->validate([
            'name' => 'required|string|max:255',
            'email' => ['required', 'email', 'max:255', Rule::unique('users', 'email')->ignore($user->id)],
            'phone' => 'nullable|string|max:40',
            'current_password' => 'required_with:password|nullable|string',
            'password' => 'nullable|string|min:8|confirmed',
        ]);

        if (! empty($data['password']) && ! Hash::check($data['current_password'] ?? '', $user->password)) {
            return response()->json([
                'message' => 'Current password is incorrect.',
                'errors' => ['current_password' => ['Current password is incorrect.']],
            ], 422);
        }

        $user->fill([
            'name' => $data['name'],
            'email' => $data['email'],
            'phone' => $data['phone'] ?? null,
        ]);
        if (! empty($data['password'])) {
            $user->password = $data['password'];
        }
        $user->save();

        return response()->json(['user' => $this->payload($user)]);
    }

    // Any signed-in role can set or remove their own profile photo (send null to remove).
    public function updateAvatar(Request $request): JsonResponse
    {
        $data = $request->validate([
            'avatar' => ['nullable', 'string', 'max:400000', 'regex:/^data:image\/(png|jpe?g|webp);base64,/'],
        ]);

        $user = $request->user();
        $user->avatar = $data['avatar'] ?? null;
        $user->save();

        return response()->json(['user' => $this->payload($user)]);
    }

    public function me(Request $request): JsonResponse
    {
        $user = $request->user();

        return response()->json([
            'user' => $this->payload($user),
            'roles' => $user->getRoleNames(),
        ]);
    }

    private function payload(User $user): array
    {
        $roles = $user->getRoleNames()->values();

        return [
            'id' => $user->id,
            'name' => $user->name,
            'email' => $user->email,
            'role' => $roles->first() ?: 'gm',
            'roles' => $roles,
            'client_id' => $user->client_id,
            'phone' => $user->phone,
            'organization' => $user->organization,
            'avatar' => $user->avatar,
            'created_at' => $user->created_at?->toIso8601String(),
        ];
    }

    public function logout(Request $request): JsonResponse
    {
        $request->user()->tokens()->delete();

        return response()->json(['message' => 'Logged out successfully.']);
    }
}