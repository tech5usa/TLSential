let mix = require('laravel-mix');

mix.setPublicPath('static');

// See https://github.com/JeffreyWay/laravel-mix/blob/master/setup/webpack.mix.js for other mix options
mix.sass('resources/scss/site.scss', 'static/css/site.css');
mix.ts('resources/js/main.ts', 'static/js/site.js');


// Disable license.txt files, see https://github.com/JeffreyWay/laravel-mix/issues/2304
mix.options({
  terser: {
    extractComments: false,
  }
})