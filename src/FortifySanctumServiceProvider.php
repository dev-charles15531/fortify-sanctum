<?php

namespace Devcharles\FortifySanctum;

use Illuminate\Support\Facades\Route;
use Illuminate\Support\ServiceProvider;
use Laravel\Fortify\Fortify;

class FortifySanctumServiceProvider extends ServiceProvider
{
    /**
     * Register services.
     */
    public function register(): void
    {
        //
    }

    /**
     * Bootstrap services.
     */
    public function boot(): void
    {
        $request = app('request');

        if ($request->wantsJson() && Fortify::$registersRoutes) {
            config(['fortify.guard' => 'sanctum']);
            config(['fortify.middleware' => str_replace('web', 'api', config('fortify.middleware', ['web']))]);
            config(['sanctum.stateful' => explode(',', str_replace(env('SANCTUM_STATEFUL_DOMAINS'), '', config(['sanctum.stateful'])))]);
            config(['cors.supports_credentials' => false]);

            Route::group([
                'domain' => config('fortify.domain', null),
                'prefix' => config('fortify.prefix'),
            ], function () {
                $this->loadRoutesFrom(__DIR__ . '/../routes/routes.php');
            });
        }
    }
}
