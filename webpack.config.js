const git = require("git-rev-sync");

const path = require('path')
const CopyPlugin = require("copy-webpack-plugin")
const webpack = require("webpack")

module.exports = {
  entry: './src/browser.ts',
  mode: "development",
  module: {
    rules: [
      {
        test: /\.tsx?$/,
        use: 'ts-loader',
        exclude: /node_modules/,
      },
      {
        test: /\.s[ac]ss$/i,
        use: [
          "style-loader",
          "css-loader",
          "sass-loader",
        ],
      },
    ],
  },
  resolve: {
    extensions: ['.tsx', '.ts', '.js'],
    fallback: {
      "crypto": require.resolve("crypto-browserify"),
      "stream": require.resolve("stream-browserify")
    }
  },
  plugins: [
    new CopyPlugin({
      patterns: [
        { from: "src/index.html", to: "index.html" },
        {
          from: "src/images/*",
          to({ context, absoluteFilename }) {
            return "[name][ext]";
          },
        },
      ],
    }),
    new webpack.ProvidePlugin({
      'jQuery': 'jquery',
    }),
    new webpack.DefinePlugin({
      COMMIT_SHA: JSON.stringify(git.long()),
    }),
  ],
  output: {
    filename: 'bundle.js',
    path: path.resolve(__dirname, 'dist'),
  },
}