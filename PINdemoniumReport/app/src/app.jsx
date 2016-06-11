import React from 'react';
import {render} from 'react-dom';


class App extends React.Component {
  render () {

    var titleStyle = {
      textAlign : 'center',
      height : '5vh',
      paddingTop : '1vh'
    }

    return (
      <div>
        <h1>HELLO WORLD!</h1>
      </div>
    );
  }
}

render(<App/>, document.getElementById('app'));