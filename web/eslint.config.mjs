import next from 'eslint-config-next'

const base = Array.isArray(next) ? next : [next]

export default [
  ...base,
  {
    files: ['src/**/*.{js,jsx,ts,tsx}'],
    rules: {
      'react/no-danger': 'error',
    },
  },
]
