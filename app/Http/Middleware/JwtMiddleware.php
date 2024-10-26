<?php

namespace App\Http\Middleware;

use Closure;
use Firebase\JWT\JWT;
use Firebase\JWT\Key;
use Illuminate\Http\Request;
use Illuminate\Http\Response as HttpResponse;
use Symfony\Component\HttpFoundation\Response;

class JwtMiddleware
{
    /**
     * Handle an incoming request.
     *
     * @param  \Closure(\Illuminate\Http\Request): (\Symfony\Component\HttpFoundation\Response)  $next
     */
    public function handle(Request $request, Closure $next): Response
    {
        $token = $request->header('Authorization');
        if (!$token) {
            return response()->json(['error'=>'Token not provided'], Response::HTTP_UNAUTHORIZED);
        }

        try {
            $token = str_replace('Bearer ','',$token);
            $decoded = JWT::decode($token, new Key(env('JWT_SECRET'),'HS256'));
            return $next($request);
        } catch (\Throwable $th) {
            return response()->json(['error'=>'Token has expired' .$th->getMessage()], Response::HTTP_UNAUTHORIZED);
        }

    }
}
