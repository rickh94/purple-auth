const defaultTheme = require('tailwindcss/defaultTheme')
module.exports = {
  content: ["./portal/templates/**/*.html"],
  theme: {
    screens: {
      'xs': '475px',
      ...defaultTheme.screens,

    },
    extend: {},
  },
  plugins: [
    require('@tailwindcss/forms')
  ],
}
