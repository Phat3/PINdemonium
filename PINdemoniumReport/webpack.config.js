var webpack = require('webpack');
var path = require('path');

// where the compiled files will reside
var BUILD_DIR = path.resolve(__dirname, 'compiled/static/js');
// where the src files that have to be compiled reside
var APP_DIR = path.resolve(__dirname, 'app/src');

var config = {
  // main of the application
  entry: APP_DIR + '/app.jsx',
  // after the build phase place the compiled file 'report_builder.js' in the output dir
  output: {
    path: BUILD_DIR,
    filename: 'report_builder.js'
  },
  // tell to webpack to use babel as converter in order to convert from ES6 to ES5
  module: {
  loaders: [
    {
      // "test" is commonly used to match the file extension
      test: /\.jsx$/,

      // "include" is commonly used to match the directories
      include: [
        APP_DIR
      ],

      // "exclude" should be used to exclude exceptions
      // try to prefer "include" when possible
      // the "loader"
      loader: "babel"
    }
  ]
}
};

module.exports = config;