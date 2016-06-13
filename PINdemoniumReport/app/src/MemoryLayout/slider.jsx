import React from 'react';

import SliderItem from './sliderItem.jsx'


class Slider extends React.Component {

   constructor(){
    super()
    this.state = { activeItem : 0 }
    this.navigateToDump = this.navigateToDump.bind(this)
  }

  // method passed as callback parameter to children components
  // this method will be called when an item on the slider is clicked
  navigateToDump(id, startDump, endDump){
    this.setState({ activeItem : id })
    this.props.onUpdate(startDump, endDump)
  }

  render () {

    var olStyle = {
        listStyle : 'none',
        width : '100%',
        textAlign : 'center',
        paddingLeft : '0px',
        paddingTop : '20px',
    }
    /*
    var items = this.props.data.map(function(row){
      return <RegisterRow key={row.id} name={row.name} content={row.content}/>
    })
    */
    var items = []    
    for (var i = 0; i < this.props.dumps.length -1 ; i++) {
      var active = false 
      var startDump = i
      var endDump = i + 1

      if( i === this.state.activeItem){
        active = true
      }
      items.push(<SliderItem key={i} id={i} onSelect={this.navigateToDump} active={active} endDump={endDump} startDump={startDump}/>)
      
    }

    return (
      <div>
         <ol style={olStyle}>
             {items}
          </ol>
      </div>
    );
  }
}

export default Slider;
