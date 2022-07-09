- [Framework enumeration](#Framework-enumeration)

### Framework enumeration
```
function angular_js_checker(){
    const elements = getAllAngularRootElements();
    const angular_version = elements[0].attributes['ng-version'];
    console.log("AngularJS verison found: " + angular_version)
}

function ember_js_checker() {
    console.log("EmberJS version found: " + Ember.VERSION);
}

function react_version_checker(){
    const react_version = React.version;
    console.log("React version found: " + react_version)
}

function vue_js_version_checker() {
    const vue_js_verison = Vue.version;
    console.log("Vue version found: " + vue_js_checker)
}

function jquery_verison_checker(){
    console.log("jQuery version found: " + jQuery().jquery)
}

function bootstrap_verison_check(){
    console.log("Bootstrap verison found: " + $.fn.tooltip.Constructor.VERSION)
}
```
