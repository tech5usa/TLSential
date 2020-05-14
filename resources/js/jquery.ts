import $ from 'jquery'

declare global {
  interface Window {
    jquery: JQueryStatic
    jQuery: JQueryStatic
    $: JQueryStatic
   }
}

// Add jQuery to the window for global support
// @TODO Phase out jQuery in favor of a modern component style setup like Vue, React, or alpine js
window.jquery = window.jQuery = window.$ = $