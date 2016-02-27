var path = require('path');

module.exports = {
  devtool: 'source-map',
  entry: './index.jsx',
  output: {
    filename: 'bundle.js',
    path: path.join(__dirname, './')
  },
  module: {
    loaders: [
      {
        test: /\.js$/,
        loader: 'babel',
        exclude: /node_modules/,
        query: {
          presets: ['es2015']
        }
      },
      {
        test: /\.css$/,
        loader: 'style-loader!css-loader',
        exclude: /node_modules/
      }
    ]
  }
};