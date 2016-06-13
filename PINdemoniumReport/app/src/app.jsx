import React from 'react';
import {render} from 'react-dom';

import MemoryLayout from './MemoryLayout/memoryLayout.jsx';


var sampleData = {
    "dumps":[
      {"eip":4220719,"end_address":4221043,"intra_writeset":false,"number":0,"start_address":4220439},
      {"eip":36990976,"end_address":36993536,"intra_writeset":false,"number":1,"start_address":36990976},
      {"eip":36900864,"end_address":36933120,"intra_writeset":false,"number":2,"start_address":36900864},
      {"eip":4198420,"end_address":4198421,"intra_writeset":false,"number":3,"start_address":4198420},
      {"eip":54135236,"end_address":54136236,"intra_writeset":false,"number":4,"start_address":54133648},
      {"eip":54138648,"end_address":54138729,"intra_writeset":false,"number":5,"start_address":54138644},
      {"eip":54138732,"end_address":54138741,"intra_writeset":false,"number":6,"start_address":54138700},
      {"eip":54138746,"end_address":54138972,"intra_writeset":false,"number":7,"start_address":54138716},
      {"eip":4198944,"end_address":4200961,"intra_writeset":false,"number":8,"start_address":4198400}
    ],

    "information": {
      "entropy":5.7108359336853027,
      "name":"write_testASprotect",
      "main_module" : {"start_address" : 4194304, "end_address" : 4259839}
    }
}


class App extends React.Component {

  constructor(){
    super()
    this.state = { data : sampleData }
  }

  render () {

    return (
      <div>

        <div className="row" id="information">
            <div className="col-sm-12">
                <h4>Information</h4>
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
}

render(<App/>, document.getElementById('app'));