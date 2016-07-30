
import React from 'react';
import {render} from 'react-dom';

import MemoryLayout from './MemoryLayout/memoryLayout.jsx';


class App extends React.Component {

  constructor(){
    super()
    this._readFile = this._readFile.bind(this)
    this.state = { data : ""}
  }

  _readFile(file){
    var rawFile = new XMLHttpRequest();
    rawFile.open("GET", file, false);
    var app = this
    rawFile.onreadystatechange = function ()
    {
        if(rawFile.readyState === 4)
        {
            if(rawFile.status === 200 || rawFile.status == 0)
            {
                var allText = rawFile.responseText;
                app.setState({data : JSON.parse(allText)})
            }
            else{
                app.setState({data : ""})
            }
        }
    }
    rawFile.send(null);
  }

  componentDidMount(){
    this._readFile("../../report_PINdemonium.txt")
  }

  render () {

    var informationStyle = {
      background: "rgba(51,51,51,1)",
      borderTop: "1px solid rgb(243, 57, 1)",
      borderBottom: "1px solid rgb(243, 57, 1)",
      marginBottom : "15px"
    }

    if(this.state.data !== ""){
        return (
          <div>

            <div className="row" id="information" style={informationStyle}>
                <div className="col-sm-12">
                   <span style={{fontSize : "18px", fontWeight : "700"}}>Name</span> : {this.state.data.information.name} <span style={{fontSize : "18px", fontWeight : "700", marginLeft : "40px"}}>Entropy</span> : {this.state.data.information.entropy}
                </div>
            </div>

            <div className="row">
                <div className="col-sm-12">
                  <MemoryLayout dumps={this.state.data.dumps} information={this.state.data.information}/>
                </div>
            </div>

          </div>
        );
    }
    else{
        return(<div></div>)
    }

  }
}

render(<App/>, document.getElementById('app'));