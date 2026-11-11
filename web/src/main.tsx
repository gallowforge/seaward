import { render } from 'preact'
import { App } from './app'
import './styles/base.css'
import './styles/page.css'
import './styles/chart.css'
import './styles/passage.css'

render(<App />, document.getElementById('app')!)
