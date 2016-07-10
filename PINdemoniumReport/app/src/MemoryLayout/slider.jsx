import React from 'react';

import SliderItem from './sliderItem.jsx'


class Slider extends React.Component {

   constructor(){
    super()
    // keep trackof the highlighted "dot"
    this.state = { activeItem : -2 }
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
    var items = [
      <SliderItem key={-2} id={-2} onSelect={this.navigateToDump} active={this.state.activeItem === -2 ? true : false} endDump={-1} startDump={-1} />,
      <SliderItem key={-1} id={-1} onSelect={this.navigateToDump} active={this.state.activeItem === -1 ? true : false} endDump={0} startDump={-1} />
    ]    
    //create an item for each dump
    for (var i = 0; i < this.props.dumps.length -1 ; i++) {
      // create the component with the proper props
      items.push(<SliderItem key={i} id={i} onSelect={this.navigateToDump} active={i === this.state.activeItem ? true : false} endDump={ i + 1} startDump={i} />)   
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

Slider.propTypes = {
  onUpdate: React.PropTypes.func.isRequired 
}

export default Slider;
